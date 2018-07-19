// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !ppc64,!ppc64le

package runtime

// This function is needed for aix/ppc64 during sighandler
// to check if the TOC is still valid.
func (c *sigctxt) sigtoc() uint64 { panic("runtime: unused") }
