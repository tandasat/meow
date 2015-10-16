// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// NOTE:
//
// About Driver Verifier:
//  This driver runs with Driver Verifier only on the ARM platform and not on
//  the x64 platform. On x64, it will quickly cause a bug check.
//
// About a certificate:
//  Executing a desktop application and installing a driver in the test-mode on
//  Windows RT 8.1 requires signing a certificate with certain Enhanced Key
//  Usage (EKU) values. Followings are simply how to make that certificate named
//  meow and sign a program with it:
//  > MakeCert /n "CN=meow" /r /h 0 /eku
//            "1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.21" /sv meow.pvk meow.cer
//  > Pvk2Pfx / pvk meow.pvk / pi password / spc meow.cer / pfx meow.pfx
//  > SignTool sign /f meow.pfx /p password /ph /fd sha256 /u
//             1.3.6.1.4.1.311.10.3.21 meow_client.exe
//

//
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

extern "C" {
#pragma warning(push, 0)
#include <fltKernel.h>
#include <Wdmsec.h>
#include <windef.h>
#include <ntimage.h>
#include <stdarg.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <intrin.h>
#include <Aux_klib.h>
#pragma warning(pop)
}

#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif
#include "../Common/ScopedResource/unique_resource.h"
#include "../Common/ScopedResource/scope_exit.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

// Specifies where the code should be located
#ifdef ALLOC_PRAGMA
#define ALLOC_TEXT(Section, Name) __pragma(alloc_text(Section, Name))
#else
#define ALLOC_TEXT(Section, Name)
#endif

// Break point that works only when a debugger is attached.
#ifndef DBG_BREAK
#ifdef _ARM_
// Nullify it since an ARM device never allow us to attach a debugger.
#define DBG_BREAK()
#else
#define DBG_BREAK()               \
  if (KD_DEBUGGER_NOT_PRESENT) {  \
  } else {                        \
    __debugbreak();               \
  }                               \
  reinterpret_cast<void *>(0)
#endif
#endif

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const ULONG MEOW_POOL_TAG_NAME = 'woem';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Returns true when it is running on the x64 system.
inline bool IsX64() {
#ifdef _AMD64_
  return true;
#else
  return false;
#endif
}
