; Copyright (c) 2015, tandasat. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements the lowest part of hook handlers.
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
    IMPORT DispgDequeuingWorkItemRoutineHookHandler
    IMPORT DispgKeWaitForSingleObjectHookHandler
    IMPORT DispgKeDelayExecutionThreadHookHandler

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
    AREA    |.text|, CODE, READWRITE

; N.B.
; All functions named Asm*HookHandler are called from trampoline code installed
; at the begging of epilogue code in corresponding kernel functions. Here is an
; example of where the trampoline code will be installed in
; KeWaitForSingleObject():
;
;   MOV             R0, R9          ; Trampoline code will be installed here
;   ADD             SP, SP, #0x5C
;   POP.W           {R4-R11,PC}
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

    EXPORT  |AsmDequeuingWorkItemRoutineHookHandler|
|AsmDequeuingWorkItemRoutineHookHandler| PROC
    NOP     ; Overwritten with an original instruction MOV R0, ?
    NOP     ; Never used (remains to be NOP)
    BL      DispgDequeuingWorkItemRoutineHookHandler
    NOP     ; Overwritten with an original epilogue instruction
    NOP     ; Ditto
    NOP     ; Ditto
    UND     #0xFE       ; __breakpoint()
    ENDP

    EXPORT  |AsmKeWaitForSingleObjectHookHandler|
|AsmKeWaitForSingleObjectHookHandler| PROC
    NOP     ; Overwritten with an original instruction MOV R0, ?
    MOV     R1, SP      ; A current stack pointer
    BL      DispgKeWaitForSingleObjectHookHandler
    NOP     ; Overwritten with an original epilogue instruction
    NOP     ; Ditto
    NOP     ; Ditto
    UND     #0xFE       ; __breakpoint()
    ENDP

    EXPORT  |AsmKeDelayExecutionThreadHookHandler|
|AsmKeDelayExecutionThreadHookHandler| PROC
    NOP     ; Overwritten with an original instruction MOV R0, ?
    MOV     R1, SP      ; A current stack pointer
    BL      DispgKeDelayExecutionThreadHookHandler
    NOP     ; Overwritten with an original epilogue instruction
    NOP     ; Ditto
    NOP     ; Ditto
    UND     #0xFE       ; __breakpoint()
    ENDP

    END

