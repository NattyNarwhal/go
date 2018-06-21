// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

DATA	_rt0_ppc64_aix+0(SB)/8, $__start<>(SB)
DATA	_rt0_ppc64_aix+8(SB)/8, $TOC(SB)
GLOBL	_rt0_ppc64_aix(SB), NOPTR, $16


TEXT __start<>(SB),NOSPLIT,$-8
	// crt0 similar code
	XOR R0, R0
	MOVD $libc___n_pthreads(SB), R4
	MOVD 0(R4), R4
	MOVD $libc___mod_init(SB), R5
	MOVD 0(R5), R5
	MOVD 0(R19), R0
	MOVD R2, 40(R1)
	MOVD 8(R19), R2
	MOVD R18, R3
	MOVD R0, CTR
	BL CTR

	MOVD 40(R1), R2
	MOVD R14, R3 // argc
	MOVD R15, R4 // argv
	MOVD $runtime·rt0_go(SB), R12
	MOVD R12, CTR
	BR (CTR)

