; Copyright (c) 2015, tandasat. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements the lowest part of hook handlers.
;
include common.inc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN DispgDequeuingWorkItemRoutineHookHandler : PROC
EXTERN DispgKeWaitForSingleObjectHookHandler : PROC
EXTERN DispgKeDelayExecutionThreadHookHandler : PROC
EXTERN DispgWaitForever : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

;
; N.B.
; All functions named Asm*HookHandler are called from trampoline code installed
; at the begging of epilogue code in corresponding kernel functions. Here is an
; example of where the trampoline code will be installed in
; KeWaitForSingleObject():
;
;   add     rsp, 48h   ; Trampoline code will be installed here
;   pop     r15
;   pop     r14
;   pop     r13
;   pop     r12
;   pop     rdi
;   pop     rsi
;   pop     rbp
;   pop     rbx
;   retn
;
; Those Asm*HookHandler() functions refer to rax because we can assume that rax 
; contains a return value of the function when the Asm*HookHandler() is called
; since it hooks only epilogue.
;
; Epilogue code overwritten by trampoline code is copied to an area allocated
; by NOP_32 macro and executed after a high level hook handler named
; Dispg*HookHandler() is processed. That restores a thread to the normal
; execution flow.
;

; A hook handler for KiCommitThreadWait(). It find a PatchGuard context by
; examining its return value (WORK_QUEUE_ITEM*).
AsmDequeuingWorkItemRoutineHookHandler PROC
    mov     rcx, rax            ; rax can be WORK_QUEUE_ITEM*
    sub     rsp, 28h
    call    DispgDequeuingWorkItemRoutineHookHandler
    add     rsp, 28h
    NOP_32
    int     3
AsmDequeuingWorkItemRoutineHookHandler ENDP

; A hook handler for KeWaitForSingleObject(). It find a PatchGuard context by
; examining its return address.
AsmKeWaitForSingleObjectHookHandler PROC
    mov     rcx, rax            ; It is not used virtually.
    mov     rdx, rsp            ; A current stack pointer
    sub     rsp, 28h
    call    DispgKeWaitForSingleObjectHookHandler
    add     rsp, 28h
    NOP_32
    int     3
AsmKeWaitForSingleObjectHookHandler ENDP


; A hook handler for KeDelayExecutionThread(). It find a PatchGuard context by
; examining its return address.
AsmKeDelayExecutionThreadHookHandler PROC
    mov     rcx, rax            ; It is not used virtually.
    mov     rdx, rsp            ; A current stack pointer
    sub     rsp, 28h
    call    DispgKeDelayExecutionThreadHookHandler
    add     rsp, 28h
    NOP_32
    int     3
AsmKeDelayExecutionThreadHookHandler ENDP


; This function is used as a new return address from KeWaitForSingleObject()
; and KeDelayExecutionThread() called by a PatchGuard context, and calls a
; function that never returns. Thus, the PatchGuard context will never resume
; that activity.
AsmWaitForever PROC
    call    DispgWaitForever    ; Using jmp instead will cause inexplicable
                                ; bug check in a following sleep function.
    int     3
AsmWaitForever ENDP

END

