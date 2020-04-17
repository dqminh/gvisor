// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fifo provides the implementation of data-link layer endpoints that
// wrap another endpoint and queues all outbound packets and asynchronously
// dispatches them to the lower endpoint.
package fifo

import (
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// endpoint represents a LinkEndpoint which implements a FIFO queue for all
// outgoing packets. endpoint can have 1 or more underlying queueDispatchers.
// All outgoing packets are consistenly hashed to a single underlying queue
// using the PacketBuffer.Hash if if set or if missing then all packets are
// queued to the first queue to avoid reordering in case of missing hash.
type endpoint struct {
	dispatcher  stack.NetworkDispatcher
	lower       stack.LinkEndpoint
	wg          sync.WaitGroup
	dispatchers []*queueDispatcher
}

// queueDispatcher is responsible for dispatching all outbound packets in it's
// queue. It will also smartly batch packets when possible and write them
// through the lower LinkEndpoint.
type queueDispatcher struct {
	lower          stack.LinkEndpoint
	q              *packetBufferQueue
	newPacketWaker sleep.Waker
	closeWaker     sleep.Waker
}

// New creates a new fifo link endpoint with the n queues with maximum
// capacity of queueLen.
func New(lower stack.LinkEndpoint, n int, queueLen int) stack.LinkEndpoint {
	e := &endpoint{
		lower: lower,
	}
	// Create the required dispatchers
	for i := 0; i < n; i++ {
		qd := &queueDispatcher{
			q:     &packetBufferQueue{limit: queueLen},
			lower: lower,
		}
		e.dispatchers = append(e.dispatchers, qd)
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			qd.dispatchLoop()
		}()
	}
	return e
}

func (q *queueDispatcher) dispatchLoop() {
	const newPacketWakerID = 1
	const closeWakerID = 2
	s := sleep.Sleeper{}
	s.AddWaker(&q.newPacketWaker, newPacketWakerID)
	s.AddWaker(&q.closeWaker, closeWakerID)
	defer s.Done()
	const batchSize = 48
	var batch stack.PacketBufferList
	for {
		id, ok := s.Fetch(true)
		if ok && id == closeWakerID {
			return
		}
		for pkt := q.q.dequeue(); pkt != nil; pkt = q.q.dequeue() {
			if batch.Len() != 0 {
				sendNow := false
				first := batch.Front()
				if pkt.Hash != first.Hash || pkt.R != first.R || pkt.Protocol != first.Protocol {
					sendNow = true
				}
				if !sendNow && ((pkt.GSOOptions != nil && first.GSOOptions == nil) || (pkt.GSOOptions == nil && first.GSOOptions != nil)) {
					sendNow = true
				}
				if !sendNow && (pkt.GSOOptions != nil && first.GSOOptions != nil) {
					if *pkt.GSOOptions != *first.GSOOptions {
						sendNow = true
					}
					// The packets can only be batched if either none of them need GSO
					// packet size < gso.MSS or if all of them need GSO.
					batchNeedsGSO := first.Data.Size() > int(first.GSOOptions.MSS)
					pktNeedsGSO := pkt.Data.Size() > int(pkt.GSOOptions.MSS)
					if batchNeedsGSO != pktNeedsGSO {
						sendNow = true
					}
				}

				if sendNow {
					q.lower.WritePackets(&first.R, first.GSOOptions, batch, first.Protocol)
					for pkt := batch.Front(); pkt != nil; pkt = pkt.Next() {
						pkt.R.Release()
						batch.Remove(pkt)
					}
					batch.Reset()
				}
			}
			batch.PushBack(pkt)
			if batch.Len() < batchSize && !q.q.empty() {
				continue
			}
			q.lower.WritePackets(&batch.Front().R, batch.Front().GSOOptions, batch, batch.Front().Protocol)
			for pkt := batch.Front(); pkt != nil; pkt = pkt.Next() {
				pkt.R.Release()
				batch.Remove(pkt)
			}
			batch.Reset()
		}
	}
}

// DeliverNetworkPacket implements the stack.NetworkDispatcher interface. It is
// called by the link-layer endpoint being wrapped when a packet arrives, and
// logs the packet before forwarding to the actual dispatcher.
func (e *endpoint) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(e, remote, local, protocol, pkt)
}

// Attach implements the stack.LinkEndpoint interface. It saves the dispatcher
// and registers with the lower endpoint as its dispatcher so that "e" is called
// for inbound packets.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.lower.Attach(e)
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It just forwards the request to the
// lower endpoint.
func (e *endpoint) MTU() uint32 {
	return e.lower.MTU()
}

// Capabilities implements stack.LinkEndpoint.Capabilities. It just forwards the
// request to the lower endpoint.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.lower.Capabilities()
}

// MaxHeaderLength implements the stack.LinkEndpoint interface. It just forwards
// the request to the lower endpoint.
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.lower.MaxHeaderLength()
}

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.lower.LinkAddress()
}

// GSOMaxSize returns the maximum GSO packet size.
func (e *endpoint) GSOMaxSize() uint32 {
	if gso, ok := e.lower.(stack.GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// WritePacket implements the stack.LinkEndpoint.WritePacket.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBuffer) *tcpip.Error {
	pkt.R = r.Clone()
	pkt.GSOOptions = gso
	pkt.Protocol = protocol
	d := e.dispatchers[int(pkt.Hash)%len(e.dispatchers)]
	if !d.q.enqueue(&pkt) {
		return tcpip.ErrNoBufferSpace
	}
	d.newPacketWaker.Assert()
	return nil
}

// WritePackets implements the stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	enqueued := 0
	for pkt := pkts.Front(); pkt != nil; {
		d := e.dispatchers[int(pkt.Hash)%len(e.dispatchers)]
		nxt := pkt.Next()
		pkt.R = r.Clone()
		pkt.GSOOptions = gso
		pkt.Protocol = r.NetProto
		if !d.q.enqueue(pkt) {
			if enqueued > 0 {
				d.newPacketWaker.Assert()
			}
			return enqueued, tcpip.ErrNoBufferSpace
		}
		pkt = nxt
		enqueued++
		d.newPacketWaker.Assert()
	}
	return enqueued, nil
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	return e.lower.WriteRawPacket(vv)
}

// Wait implements stack.LinkEndpoint.Wait.
func (e *endpoint) Wait() {
	e.lower.Wait()

	// The linkEP is gone now tear down our the outbound dispatcher
	// goroutines.
	for i := range e.dispatchers {
		e.dispatchers[i].closeWaker.Assert()
	}

	e.wg.Wait()
}
