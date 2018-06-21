// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build aix
// +build ppc64 ppc64le

//
// System calls and other sys.stuff for ppc64, Aix
//

#include "go_asm.h"
#include "go_tls.h"
#include "textflag.h"
#include "asm_ppc64x.h"

TEXT runtime·asmsyscall6(SB),NOSPLIT|NOFRAME,$0
	MOVD	libcall_fn(R3), R12
	MOVD	libcall_args(R3), R9
	MOVD	0(R9), R3
	MOVD	8(R9), R4
	MOVD	16(R9), R5
	MOVD	24(R9), R6
	MOVD	32(R9), R7
	MOVD	40(R9), R8

	MOVD	0(R12), R12
	MOVD	R2, 24(R1)
	MOVD	0(R12), R0
	MOVD	8(R12), R2
	MOVD	R0, CTR
	BR	(CTR)


TEXT runtime·sigfwd(SB),NOSPLIT,$0-32
	MOVW	sig+8(FP), R3
	MOVD	info+16(FP), R4
	MOVD	ctx+24(FP), R5
	MOVD	fn+0(FP), R12
	MOVD	R12, CTR
	BL	(CTR)
	RET


// function descriptor for the real sigtramp
DATA	runtime·sigtramp+0(SB)/8, $runtime·_sigtramp(SB)
DATA	runtime·sigtramp+8(SB)/8, $TOC(SB)
GLOBL	runtime·sigtramp(SB), NOPTR, $16

TEXT runtime·_sigtramp(SB),NOSPLIT,$64
	// initialize essential registers (just in case)
	BL	runtime·reginit(SB)
	BL	runtime·load_g(SB)

	MOVW	R3, FIXED_FRAME+0(R1)
	MOVD	R4, FIXED_FRAME+8(R1)
	MOVD	R5, FIXED_FRAME+16(R1)
	MOVD	$runtime·sigtrampgo(SB), R12
	MOVD	R12, CTR
	BL	(CTR)
	RET

// function descriptor for the real tstart
DATA	runtime·tstart+0(SB)/8, $runtime·_tstart(SB)
DATA	runtime·tstart+8(SB)/8, $TOC(SB)
GLOBL	runtime·tstart(SB), NOPTR, $16

TEXT runtime·_tstart(SB),NOSPLIT,$0
	XOR	 R0, R0 // reset R0

	// set g
	MOVD	m_g0(R3), g

	// Layout new m scheduler stack on os stack.
	MOVD	R1, R3
	MOVD	R3, (g_stack+stack_hi)(g)
	SUB	$(const_threadStackSize), R3		// stack size
	MOVD	R3, (g_stack+stack_lo)(g)
	ADD	$const__StackGuard, R3
	MOVD	R3, g_stackguard0(g)
	MOVD	R3, g_stackguard1(g)

	BL	runtime·save_g(SB)

	BL	runtime·mstart(SB)

	MOVD R0, R3
	RET

// Runs on OS stack, called from runtime·osyield.
TEXT runtime·osyield1(SB),NOSPLIT,$0
	MOVD	$libc_sched_yield(SB), R12
	MOVD	0(R12), R12
	MOVD	R2, 40(R1)
	MOVD	0(R12), R0
	MOVD	8(R12), R2
	MOVD	R0, CTR
	BL	(CTR)
	MOVD	40(R1), R2
	RET
