;;
;; Copyright 2017-2022 Secure Thingz Ltd.
;; All rights reserved.
;;
;; This source file and its use is subject to a Secure Thingz Embedded Trust
;; License agreement. This source file may contain licensed source code from
;; other third-parties and is subject to those license agreements as well.
;;
;; Permission to use, copy, modify, compile and distribute compiled binary of the
;; source code for use as specified in the Embedded Trust license agreement is
;; hereby granted provided that the this copyright notice and other third-party
;; copyright notices appear in all copies of the source code.
;;
;; Distribution of Embedded Trust source code in any form is governed by the
;; Embedded Trust license agreement. Use of the Secure Thingz name or trademark
;; in any form is prohibited.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
;; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
;; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
;; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
;; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
;; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;; POSSIBILITY OF SUCH DAMAGE.
;;

        MODULE  ?arm_core_exceptions

;;
;; The generic Cortex exceptions are funneled into C code via
;; a common trampoline.
;;
;; Firstly, declare the trampoline to C-SPY.
;; Shamelessly purloined from IAR's example exception ASM code.
;;
	CFI Names cfiNames0
	CFI StackFrame CFA R13 DATA
	CFI Resource R0:32, R1:32, R2:32, R3:32, R4:32, R5:32, R6:32, R7:32
	CFI Resource R8:32, R9:32, R10:32, R11:32, R12:32, R13:32, R14:32
	CFI EndNames cfiNames0

	CFI Common cfiCommon0 Using cfiNames0
	CFI CodeAlign 2
	CFI DataAlign 4
	CFI ReturnAddress R14 CODE
	CFI CFA R13+0
	CFI R0 Undefined
	CFI R1 Undefined
	CFI R2 SameValue
	CFI R3 SameValue
	CFI R4 SameValue
	CFI R5 SameValue
	CFI R6 SameValue
	CFI R7 SameValue
	CFI R8 SameValue
	CFI R9 SameValue
	CFI R10 SameValue
	CFI R11 SameValue
	CFI R12 SameValue
	CFI R14 Undefined
	CFI EndCommon cfiCommon0

	SECTION .text:CODE:NOROOT:REORDER(2)
    THUMB
	EXTERN	cpu_fault_handler
	PUBLIC	NMI_Handler
	PUBLIC	HardFault_Handler
	PUBLIC	MemManage_Handler
	PUBLIC	BusFault_Handler
	PUBLIC	UsageFault_Handler
	PUBLIC	DebugMon_Handler
	PUBLIC	PendSV_Handler

	CFI Block cfiBlock0 Using cfiCommon0
	CFI Function __exception_trampoline

;;
;; We arrange for the following exceptions to be handled by the
;; cpu_fault_handler() function, but not before saving some more
;; context for diagnostic purposes.
;;
NMI_Handler
HardFault_Handler
MemManage_Handler
BusFault_Handler
UsageFault_Handler
DebugMon_Handler
PendSV_Handler
__exception_trampoline
	CALL_GRAPH_ROOT __exception_trampoline, "interrupt"
	NOCALL __exception_trampoline

	;; The trampoline begins here...
#if (defined(__ARM_FEATURE_CMSE) && \
     defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
	MOV	R1, LR
	LSLS	R1, R1, #25	; Came from Secure/Non-Secure?
	BMI.N	?sec		; Jump if Secure
	MRS	R0, MSP_NS	; Assume main_SP_NS was active
	MRS	R1, CONTROL_NS	; Need to use CONTROL_NS to determine active SP.
	LSLS	R1, R1, #30	; Assumption correct?
	BPL.N	?save		; Jump if yes
	MRS	R0, PSP_NS	; Otherwise fetch process_SP_NS
	B.N	?save
?sec:
	MRS	R0, MSP		; Assume main_SP was active.
	LSLS	R1, R1, #4	; Test if our assumption was correct
	BPL.N	?save		; Jump if yes.
	MRS	R0, PSP		; Otherwise fetch process_SP.

#else

	MRS	R0, MSP		; Assume main_SP was active.
	MOV	R1, LR
	LSLS	R1, R1, #29	; Test if our assumption was correct
	BPL.N	?save		; Jump if yes.
	MRS	R0, PSP		; Otherwise fetch process_SP.
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */

?save:
#if (__ARM_ARCH_ISA_THUMB == 1)
	PUSH	{R2,LR}		; Push Padding & LR (EXCRET)
	PUSH	{R4-R7}		; Save R4-R7
	MOV	R4, R8		; Need to jump through some hoops
	MOV	R5, R9		; on Cortex-M0 to save registers
	MOV	R6, R10		; R8-R11
	MOV	R7, R11
	PUSH	{R4-R7}
#else
	PUSH	{R4-R12, LR}	; Save additional register state
#endif /* (__ARM_ARCH_ISA_THUMB == 1) */

	MOV	R1, SP

	;; Tell C-SPY we updated the stack pointer and are about to
	;; invoke the C function.
	CFI	cfa r13+40
	CFI	funcall cpu_fault_handler

	BL	cpu_fault_handler ; Invoke the C handler.

#if (__ARM_ARCH_ISA_THUMB == 1)
	POP	{R4-R7}		; Restore R8-R11
	MOV	R8, R4
	MOV	R9, R5
	MOV	R10, R6
	MOV	R11, R7
	POP	{R4-R7}		; Restore R4-R7
	POP	{R2,PC}		; Ditch padding and return
#else
	POP	{R4-R12, PC}	; Return from the exception.
#endif /* (__ARM_ARCH_ISA_THUMB == 1) */

	;; Tell C-SPY the stack is restored
	CFI	cfa r13

	CFI EndBlock cfiBlock0

	PUBWEAK	SVC_Handler
	SECTION	.text:CODE:NOROOT:REORDER(1)
SVC_Handler
	B	SVC_Handler

	SECTION .text:CODE:NOROOT:REORDER(2)
	THUMB
	EXTERN	SysTick_Implementation
	PUBLIC	SysTick_Handler
SysTick_Handler
	MRS	R0, MSP		; Assume main_SP was active.
	MOV	R1, LR
	LSLS	R1, R1, #29	; Test if our assumption was correct
#if (__ARM_ARCH_ISA_THUMB == 1)
	BPL.N	?systick_jump	; Jump if yes.
#else
	BPL.W	SysTick_Implementation
#endif /* (__ARM_ARCH_ISA_THUMB == 1) */
	MRS	R0, PSP		; Otherwise fetch process_SP.
#if (__ARM_ARCH_ISA_THUMB == 1)
?systick_jump:
	LDR	R1,=SysTick_Implementation
	BX	R1
#else
        B	SysTick_Implementation
#endif /* (__ARM_ARCH_ISA_THUMB == 1) */

        END
