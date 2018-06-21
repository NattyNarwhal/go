// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"runtime/internal/atomic"
	"unsafe"
)

//go:cgo_import_dynamic libc_pollset_create pollset_create "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_pollset_ctl pollset_ctl "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_pollset_poll pollset_poll "libc.a/shr_64.o"

//go:linkname libc_pollset_create libc_pollset_create
//go:linkname libc_pollset_ctl libc_pollset_ctl
//go:linkname libc_pollset_poll libc_pollset_poll

var (
	libc_pollset_create,
	libc_pollset_ctl,
	libc_pollset_poll libFunc
)

type pollset_t int32

type pollfd struct {
	fd      int32
	events  int16
	revents int16
}

const _POLLIN = 0x0001
const _POLLOUT = 0x0002
const _POLLHUP = 0x2000
const _POLLERR = 0x4000
const _O_NONBLOCK = 0x4

type poll_ctl struct {
	cmd    int16
	events int16
	fd     int32
}

const _PS_ADD = 0x0
const _PS_DELETE = 0x2

//go:nosplit
func pollset_create(maxfd int32) (pollset_t, int32) {
	r, err := syscall1(&libc_pollset_create, uintptr(maxfd))
	return pollset_t(r), int32(err)
}

//go:nosplit
func pollset_ctl(ps pollset_t, pollctl_array *poll_ctl, array_length int32) (int32, int32) {
	r, err := syscall3(&libc_pollset_ctl, uintptr(ps), uintptr(unsafe.Pointer(pollctl_array)), uintptr(array_length))
	return int32(r), int32(err)
}

//go:nosplit
func pollset_poll(ps pollset_t, polldata_array *pollfd, array_length int32, timeout int32) (int32, int32) {
	r, err := syscall4(&libc_pollset_poll, uintptr(ps), uintptr(unsafe.Pointer(polldata_array)), uintptr(array_length), uintptr(timeout))
	return int32(r), int32(err)
}

func fcntl(fd, cmd int32, arg uintptr) int32 {
	r, _ := syscall3(&libc_fcntl, uintptr(fd), uintptr(cmd), arg)
	return int32(r)
}

var (
	ps          pollset_t = -1
	mpfds       map[int32]*pollDesc
	pmtx        mutex
	rdwake      int32
	wrwake      int32
	needsUpdate uint32
)

func netpollinit() {
	var p [2]int32

	if ps, _ = pollset_create(-1); ps < 0 {
		throw("runtime: netpollinit failed to create pollset")
	}
	// It is not possible to add or remove descriptors from
	// the pollset while pollset_poll is active.
	// We use a pipe to wakeup pollset_poll when the pollset
	// needs to be updated.
	if r := pipe(&p[0]); r < 0 {
		throw("runtime: netpollinit failed to create pipe")
	}
	rdwake = p[0]
	wrwake = p[1]

	fl := uintptr(fcntl(rdwake, _F_GETFL, 0))
	fcntl(rdwake, _F_SETFL, fl|_O_NONBLOCK)
	fcntl(rdwake, _F_SETFD, _FD_CLOEXEC)

	fl = uintptr(fcntl(wrwake, _F_GETFL, 0))
	fcntl(wrwake, _F_SETFL, fl|_O_NONBLOCK)
	fcntl(wrwake, _F_SETFD, _FD_CLOEXEC)

	// Add the read side of the pipe to the pollset.
	var pctl poll_ctl
	pctl.cmd = _PS_ADD
	pctl.fd = rdwake
	pctl.events = _POLLIN
	if r, _ := pollset_ctl(ps, &pctl, 1); r != 0 {
		throw("runtime: netpollinit failed to register pipe")
	}

	mpfds = make(map[int32]*pollDesc)
}

func netpolldescriptor() uintptr {
	// ps is not a real file descriptor.
	return ^uintptr(0)
}

func netpollopen(fd uintptr, pd *pollDesc) int32 {
	// pollset_ctl will block if pollset_poll is active
	// so wakeup pollset_poll first.
	atomic.Store(&needsUpdate, 1)
	b := [1]byte{0}
	write(uintptr(wrwake), unsafe.Pointer(&b[0]), 1)

	var pctl poll_ctl
	pctl.cmd = _PS_ADD
	pctl.fd = int32(fd)
	pctl.events = _POLLIN | _POLLOUT
	if r, err := pollset_ctl(ps, &pctl, 1); r != 0 {
		return err
	}
	lock(&pmtx)
	mpfds[int32(fd)] = pd
	atomic.Store(&needsUpdate, 0)
	unlock(&pmtx)

	return 0
}

func netpollclose(fd uintptr) int32 {
	// pollset_ctl will block if pollset_poll is active
	// so wakeup pollset_poll first.
	atomic.Store(&needsUpdate, 1)
	b := [1]byte{0}
	write(uintptr(wrwake), unsafe.Pointer(&b[0]), 1)

	var pctl poll_ctl
	pctl.cmd = _PS_DELETE
	pctl.fd = int32(fd)

	if r, err := pollset_ctl(ps, &pctl, 1); r != 0 {
		return err
	}
	lock(&pmtx)
	delete(mpfds, int32(fd))
	atomic.Store(&needsUpdate, 0)
	unlock(&pmtx)

	return 0
}

func netpollarm(pd *pollDesc, mode int) {
	throw("runtime: unused")
}

func netpoll(block bool) *g {
	if ps == -1 {
		return nil
	}
	timeout := int32(-1)
	if !block {
		timeout = 0
	}
	var pfds [128]pollfd
retry:
	for atomic.Load(&needsUpdate) > 0 {
		if !block {
			return nil
		}
		osyield()
	}

	nfound, e := pollset_poll(ps, &pfds[0], int32(len(pfds)), timeout)
	if nfound < 0 {
		if e != _EINTR {
			throw("runtime: pollset_poll failed")
		}
		goto retry
	}
	var gp guintptr
	for i := int32(0); i < nfound; i++ {
		pfd := &pfds[i]

		var mode int32
		if pfd.revents&(_POLLIN|_POLLHUP|_POLLERR) != 0 {
			if pfd.fd == rdwake {
				var b [1]byte
				read(pfd.fd, unsafe.Pointer(&b[0]), 1)
				continue
			}
			mode += 'r'
		}
		if pfd.revents&(_POLLOUT|_POLLHUP|_POLLERR) != 0 {
			mode += 'w'
		}
		if mode != 0 {
			lock(&pmtx)
			pd := mpfds[pfd.fd]
			unlock(&pmtx)
			if pd != nil {
				netpollready(&gp, pd, mode)
			}
		}
	}
	if block && gp == 0 {
		goto retry
	}
	return gp.ptr()
}
