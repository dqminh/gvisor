// Copyright 2019 The gVisor Authors.
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

// Package test1 is a test package.
package test1

import (
	"fmt"
	"reflect"
)

// Interface is a generic interface.
type Interface interface {
	Foo()
}

// Type is a concrete implementation of Interface.
type Type struct {
	A uint64
	B uint64
}

// Foo implements Interface.Foo.
//go:nosplit
func (t Type) Foo() {
	fmt.Printf("%v", t) // Never executed.
}

// +checkescape:all,hard
//go:nosplit
func InterfaceFunction(i Interface) {
	// Do nothing; exported for tests.
}

// +checkesacape:all,hard
//go:nosplit
func TypeFunction(t *Type) {
}

// +testescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinMap(x int) map[string]bool {
	return make(map[string]bool)
}

// +testescape:builtin
//go:noinline
//go:nosplit
func builtinMapRec(x int) map[string]bool {
	return BuiltinMap(x)
}

// +testescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinClosure(x int) func() {
	return func() {
		fmt.Printf("%v", x)
	}
}

// +testescape:builtin
//go:noinline
//go:nosplit
func builtinClosureRec(x int) func() {
	return BuiltinClosure(x)
}

// +testescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinMakeSlice(x int) []byte {
	return make([]byte, x)
}

// +testescape:builtin
//go:noinline
//go:nosplit
func builtinMakeSliceRec(x int) []byte {
	return BuiltinMakeSlice(x)
}

// +testescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinAppend(x []byte) []byte {
	return append(x, 0)
}

// +testescape:builtin
//go:noinline
//go:nosplit
func builtinAppendRec() []byte {
	return BuiltinAppend(nil)
}

// +testescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinChan() chan int {
	return make(chan int)
}

// +testescape:builtin
//go:noinline
//go:nosplit
func builtinChanRec() chan int {
	return BuiltinChan()
}

// +testescape:local,heap
//go:noinline
//go:nosplit
func Heap() *Type {
	var t Type
	return &t
}

// +testescape:heap
//go:noinline
//go:nosplit
func heapRec() *Type {
	return Heap()
}

// +testescape:local,interface
//go:noinline
//go:nosplit
func Dispatch(i Interface) {
	i.Foo()
}

// +testescape:interface
//go:noinline
//go:nosplit
func dispatchRec(i Interface) {
	Dispatch(i)
}

// +testescape:local,dynamic
//go:noinline
//go:nosplit
func Dynamic(f func()) {
	f()
}

// +testescape:dynamic
//go:noinline
//go:nosplit
func dynamicRec(f func()) {
	Dynamic(f)
}

// +testescape:local,unknown
//go:noinline
//go:nosplit
func Unknown() {
	_ = reflect.TypeOf((*Type)(nil)) // Does not actually escape.
}

// +testescape:unknown
//go:noinline
//go:nosplit
func unknownRec() {
	Unknown()
}

//go:noinline
//go:nosplit
func internalFunc() {
}

// +testescape:local,stack
//go:noinline
func Split() {
	internalFunc()
}

// +testescape:stack
//go:noinline
func splitRec() {
	Split()
}
