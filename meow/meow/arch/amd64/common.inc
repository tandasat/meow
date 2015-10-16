; Copyright (c) 2015, tandasat. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements common macros
;

; Inserts space of 32 bytes for runtime code modification.
NOP_32 MACRO
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop     ; 10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop     ; 20
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop     ; 30
    nop
    nop
ENDM

