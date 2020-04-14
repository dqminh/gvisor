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

package udp_icmp_error_propagation_test

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

type connected bool

func (c connected) String() string {
	if c {
		return "Connected"
	}
	return "Connectionless"
}

type icmpError int

const (
	portUnreachable icmpError = iota
	timeToLiveExceeded
)

func (e icmpError) String() string {
	switch e {
	case portUnreachable:
		return "PortUnreachable"
	case timeToLiveExceeded:
		return "TimeToLiveExpired"
	}
	return "Unknown ICMP error"
}

func (e icmpError) ToICMPv4() *tb.ICMPv4 {
	switch e {
	case portUnreachable:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4DstUnreachable), Code: tb.Uint8(header.ICMPv4PortUnreachable)}
	case timeToLiveExceeded:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4TimeExceeded), Code: tb.Uint8(header.ICMPv4TTLExceeded)}
	}
	return nil
}

type errorDetection int

const (
	sendTo errorDetection = iota
	recv
	errQueue // TODO Test recvmsg with MSG_ERRQUEUE flag.
	sockOpt
)

func (e errorDetection) String() string {
	switch e {
	case sendTo:
		return "SendTo"
	case recv:
		return "Recv"
	case errQueue:
		return "ErrQueue"
	case sockOpt:
		return "SockOpt"
	}
	return "UnknownErrorDetectionMethod"
}

func test(t *testing.T, c connected, icmpError icmpError, e errorDetection, expected syscall.Errno) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()

	remoteFd, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(remoteFd)

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	if c {
		dut.Connect(remoteFd, conn.LocalAddr())
	}

	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	udp, err := conn.Expect(tb.UDP{}, time.Second)
	if err != nil {
		t.Fatalf("did not receive message from DUT: %s", err)
	}

	if icmpError == timeToLiveExceeded {
		ip, ok := udp.Prev().(*tb.IPv4)
		if !ok {
			t.Fatalf("expected %s to be IPv4", udp.Prev())
		}
		*ip.TTL = 0
		// Let serialization recalculate the checksum since we set the
		// TTL to 0.
		ip.Checksum = nil

		// Note that the ICMP payload is valid in this case because the UDP
		// payload is empty. If the UDP payload were not empty, the packet
		// length during serialization may not be calculated correctly,
		// resulting in a mal-formed packet.
		conn.SendIP(icmpError.ToICMPv4(), ip, udp)
	} else {
		conn.SendIP(icmpError.ToICMPv4(), udp.Prev(), udp)
	}

	switch e {
	case sendTo:
		if expected == syscall.Errno(0) {
			dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
			_, err := conn.Expect(tb.UDP{}, time.Second)
			if err != nil {
				t.Fatalf("did not receive UDP packet as expected: %s", err)
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ret, err := dut.SendToWithErrno(ctx, remoteFd, nil, 0, conn.LocalAddr())

			if ret != -1 {
				t.Fatalf("sendto after ICMP error succeeded unexpectedly")
			}
			if err != expected {
				t.Fatalf("sendto after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, expected)
			}

			// Next send should work.
			dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
			_, err = conn.Expect(tb.UDP{}, time.Second)
			if err != nil {
				t.Fatalf("second sendto failed: %s", err)
			}
		}
	case recv:
		if expected == syscall.Errno(0) {
			conn.Send(tb.UDP{})
			dut.Recv(remoteFd, 100, 0)
		} else {
			conn.Send(tb.UDP{})

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ret, _, err := dut.RecvWithErrno(ctx, remoteFd, 100, 0)
			if ret != -1 {
				t.Fatalf("recv after ICMP error succeeded unexpectedly")
			}
			if err != expected {
				t.Fatalf("recv after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, expected)
			}

			// Next recv should work.
			dut.Recv(remoteFd, 100, 0)
		}
	case sockOpt:
		errno := syscall.Errno(dut.GetSockOptInt(remoteFd, unix.SOL_SOCKET, unix.SO_ERROR))
		if errno != expected {
			t.Fatalf("SO_ERROR sockopt after ICMP error is (%[1]d) %[1]v, expected (%[2]d) %[2]v", errno, expected)
		}

		// Check that after clearing socket error, sending doesn't fail.
		dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
		conn.Expect(tb.UDP{}, time.Second)
	}
}

func TestUdpIcmpErrorPropagation(t *testing.T) {
	for _, tt := range []struct {
		c     connected
		i     icmpError
		e     errorDetection
		errno syscall.Errno
	}{
		{true, portUnreachable, sendTo, unix.ECONNREFUSED},
		{true, portUnreachable, recv, unix.ECONNREFUSED},
		{true, portUnreachable, sockOpt, unix.ECONNREFUSED},
		{false, portUnreachable, sendTo, syscall.Errno(0)},
		{false, portUnreachable, recv, syscall.Errno(0)},
		{false, portUnreachable, sockOpt, syscall.Errno(0)},
		{true, timeToLiveExceeded, sendTo, syscall.Errno(0)},
		{true, timeToLiveExceeded, recv, syscall.Errno(0)},
		{true, timeToLiveExceeded, sockOpt, syscall.Errno(0)},
		{false, timeToLiveExceeded, sendTo, syscall.Errno(0)},
		{false, timeToLiveExceeded, recv, syscall.Errno(0)},
		{false, timeToLiveExceeded, sockOpt, syscall.Errno(0)},
	} {
		t.Run(fmt.Sprintf("%s%s%s", tt.c, tt.i, tt.e), func(t *testing.T) {
			test(t, tt.c, tt.i, tt.e, tt.errno)
		})
	}
}
