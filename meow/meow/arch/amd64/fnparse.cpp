// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements Function Parse functions.
//
#include "stdafx.h"
#include "fnparse.h"
#include "util.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// http://msdn.microsoft.com/en-us/library/0kd71y96.aspx
typedef enum _UNWIND_OP_CODES {
  UWOP_PUSH_NONVOL = 0, /* info == register number */
  UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
  UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
  UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
  UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
  UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
  UWOP_SAVE_XMM128,     /* info == XMM reg number, offset in next slot */
  UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
  UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef struct _UNWIND_CODE {
  BYTE CodeOffset;
  BYTE UnwindOp : 4;
  BYTE OpInfo : 4;
} UNWIND_CODE, *PUNWIND_CODE;
static_assert(sizeof(UNWIND_CODE) == 2, "Size check");

typedef struct _UNWIND_INFO {
  BYTE Version : 3;
  BYTE Flags : 5;
  BYTE SizeOfProlog;
  BYTE CountOfCodes;
  BYTE FrameRegister : 4;
  BYTE FrameOffset : 4;
  UNWIND_CODE UnwindCode[1];
  /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
  *   union {
  *       OPTIONAL ULONG ExceptionHandler;
  *       OPTIONAL ULONG FunctionEntry;
  *   };
  *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

#ifndef UNW_FLAG_NHANDLER
#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4
#endif

// Represents byte codes of instructions used for epilogue.
struct EpilogueOpcode {
  static const ULONG AddRsp = 0xffc48348;  // 0xff will be replaced with real
                                           // stack size.
  static const UCHAR PopRax = 0x58;
  static const UCHAR PopRcx = 0x59;
  static const UCHAR PopRdx = 0x5a;
  static const UCHAR PopRbx = 0x5b;
  static const UCHAR PopRsp = 0x5c;
  static const UCHAR PopRbp = 0x5d;
  static const UCHAR PopRsi = 0x5e;
  static const UCHAR PopRdi = 0x5f;
  static const USHORT PopR8 = 0x5841;
  static const USHORT PopR9 = 0x5941;
  static const USHORT PopR10 = 0x5a41;
  static const USHORT PopR11 = 0x5b41;
  static const USHORT PopR12 = 0x5c41;
  static const USHORT PopR13 = 0x5d41;
  static const USHORT PopR14 = 0x5e41;
  static const USHORT PopR15 = 0x5f41;
  static const UCHAR Retn = 0xc3;
};

// Stores an EpilogueOpcode entry.
struct EpilogueOpcodeInfo {
  ULONG Bytes;  // such as PopRax (58 00 00 00)
  ULONG Size;   // such as 1 for PopRax.
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C IMAGE_RUNTIME_FUNCTION_ENTRY *NTAPI
RtlLookupFunctionEntry(_In_ PVOID ControlPc, _Out_ PVOID *ImageBase,
                       _Inout_opt_ struct UNWIND_HISTORY_TABLE *HistoryTable);

EXTERN_C static EpilogueInfo FnparsepGetFunctionEpilogueInfo(
    _In_ UCHAR *FunctionAddress);

EXTERN_C static UCHAR *FnparsepInterpretAllocSmallOp(_In_ UCHAR OpInfo,
                                                     _Inout_ UCHAR *Epilogue);

EXTERN_C static UCHAR *FnparsepInterpretPushNonVolOp(_In_ UCHAR OpInfo,
                                                     _Inout_ UCHAR *Epilogue);

EXTERN_C static EpilogueOpcodeInfo FnparsepGetPushNonVolOpInfo(
    _In_ UCHAR OpInfo);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Wrapper for RtlLookupFunctionEntry().
ALLOC_TEXT(PAGED, FnparseLookupFunctionEntry)
_Use_decl_annotations_ EXTERN_C IMAGE_RUNTIME_FUNCTION_ENTRY *
FnparseLookupFunctionEntry(FARPROC FunctionAddress, PVOID *ImageBase) {
  PAGED_CODE();

  return RtlLookupFunctionEntry(FunctionAddress, ImageBase, nullptr);
}

// Tries to determine a length of the function and return it. Beware that this
// function does not guarantee the correct result due to the fact that
// functions can be formed in any ways.
ALLOC_TEXT(PAGED, FnparseGetFunctionLength)
_Use_decl_annotations_ EXTERN_C SIZE_T
FnparseGetFunctionLength(UCHAR *FunctionAddress) {
  PAGED_CODE();

  //
  // Get a range described in .pdata for a function entry point. That is often
  // a range of the function but not always. If there is a .pdata for the end
  // of the function's address, this function assume that it is still in a
  // range of the function. For example, the function recognizes a function
  // range as 0x1000 to 0x102f since the end of the first range and the
  // beginning of the second range is the same, and the third range is
  // separated from the end of the second range.
  //
  //  0x1000 { beginning of the function
  //  0x1010 } end of the range
  //  0x1010 { beginning of a new range
  //  0x102f } end of the range
  //  0x1030 { beginning of a new range
  //  0x1050 } end of the range
  //
  UCHAR *base = nullptr;
  SIZE_T begin = 0;
  SIZE_T end = 0;
  for (auto address = FunctionAddress;; address = base + end) {
    auto entry = FnparseLookupFunctionEntry(
        UtilDataToFp(reinterpret_cast<UCHAR *>(address)),
        reinterpret_cast<void **>(&base));
    if (!entry) {
      // A .pdata entry corresponding the address not found. Meaning that it is
      // either not a function address or there is no .pdata for the end of the
      // range.
      return end - begin;
    }
    if (!begin) {
      // The beginning of the function will not be changed.
      begin = entry->BeginAddress;
    }
    // Try to find a next .pdata using the end of the range.
    end = entry->EndAddress;
  }
}

// Retrieves the given function's epilogue address(es), epilogue length and
// stack
// size, or returns empty information when it failed to solve any of them. This
// function is not meant to cover all functions. It is merely designed to be
// able
// to handle a good enough range of functions for this project's purpose.
//
// Here is an example of where it returns as an epilogue address:
//
// On x64:
//  mov     rax, rcx
//  add     rsp, 48h            ; this address will be returned.
//  pop     rbp
//  pop     rbx
//  retn
//
ALLOC_TEXT(PAGED, FnparseGetEpilogueInfo)
_Use_decl_annotations_ EXTERN_C EpilogueInfo
FnparseGetEpilogueInfo(UCHAR *FunctionAddress) {
  PAGED_CODE();

  // This function presumes byte codes of the function's epilogue from unwind
  // information, then searches it in the range of the function in order to
  // find epilogue code. Apart from that, it calculates unwind stack size from
  // unwind information too.

  UCHAR *base = nullptr;
  auto entry = FnparseLookupFunctionEntry(
      UtilDataToFp(reinterpret_cast<UCHAR *>(FunctionAddress)),
      reinterpret_cast<void **>(&base));
  if (!entry) {
    return {};
  }

  // Do not suppose anything has value in Flags for the sake of ease of
  // implementation and testing.
  auto unwind =
      reinterpret_cast<UNWIND_INFO *>(entry->UnwindInfoAddress + base);
  if (unwind->Flags != UNW_FLAG_NHANDLER) {
    return {};
  }

  // Allocates a big enough memory to save epilogue byte code.
  auto epilogueBytesAllocationSize = unwind->SizeOfProlog + 1;  // +1 for ret.
  auto epilogueBytesNaked = reinterpret_cast<BYTE *>(ExAllocatePoolWithTag(
      PagedPool, epilogueBytesAllocationSize, MEOW_POOL_TAG_NAME));
  if (!epilogueBytesNaked) {
    return {};
  }
  auto epilogueBytesCleaner =
      std::experimental::make_scope_exit([epilogueBytesNaked]() {
        ExFreePoolWithTag(epilogueBytesNaked, MEOW_POOL_TAG_NAME);
      });
  memset(epilogueBytesNaked, 0, epilogueBytesAllocationSize);

  // Enumerates all unwind operation codes.
  auto current = epilogueBytesNaked;  // A current position in epilogueBytes.
  auto stackSize = 0ul;
  auto isExpectingAllocSmall = true;
  for (auto i = 0ul; i < unwind->CountOfCodes; ++i) {
    const auto &code = unwind->UnwindCode[i];

    if (isExpectingAllocSmall) {
      // Ignore until UWOP_ALLOC_SMALL shows up first.
      if (code.UnwindOp == UWOP_ALLOC_SMALL) {
        current = FnparsepInterpretAllocSmallOp(code.OpInfo, current);
        stackSize += (code.OpInfo * 8) + 8;
        isExpectingAllocSmall = false;
      }
    } else {
      // Once UWOP_ALLOC_SMALL was processed, it interprets necessary operation
      // codes.
      switch (code.UnwindOp) {
        case UWOP_PUSH_NONVOL:
          current = FnparsepInterpretPushNonVolOp(code.OpInfo, current);
          stackSize += 8;
          break;
        default:
          return {};  // Error. Unexpected operation code.
      }
    }

    // Error. Opcode interpretation failed.
    if (!current) {
      return {};
    }
  }

  // Copy a ret instruction at the end.
  memcpy(current, &EpilogueOpcode::Retn, sizeof(EpilogueOpcode::Retn));
  current++;

  // Get an actual epilogue size.
  const auto epilogueSize = current - epilogueBytesNaked;

  // Get a function length.
  const auto length = FnparseGetFunctionLength(FunctionAddress);
  if (!length) {
    return {};
  }

  // Find an address of epilogue.
  auto epilogueAddress = reinterpret_cast<UCHAR *>(
      UtilMemMem(FunctionAddress, length, epilogueBytesNaked, epilogueSize));
  if (!epilogueAddress) {
    return {};
  }

  return {
      epilogueSize,
      stackSize,
      {
          epilogueAddress,
      },
  };
}

// Handles an unwind operation code UWOP_ALLOC_SMALL and returns an address
// where to use next in Epilogue, or returns nullptr in case of error.
ALLOC_TEXT(PAGED, FnparsepInterpretAllocSmallOp)
_Use_decl_annotations_ EXTERN_C static UCHAR *FnparsepInterpretAllocSmallOp(
    UCHAR OpInfo, UCHAR *Epilogue) {
  PAGED_CODE();

  // The size of the allocation is the operation info field * 8 + 8, allowing
  // allocations from 8 to 128 bytes.
  const auto stackSize = OpInfo * 8 + 8;
  if (stackSize > 128) {
    return nullptr;
  }

  union {
    ULONG Value;
    UCHAR Bytes[4];
  } info;
  static_assert(sizeof(info) == 4, "Size check");

  // Build an instruction 'add rsp, stackSize'.
  info.Value = EpilogueOpcode::AddRsp;
  info.Bytes[3] = static_cast<UCHAR>(stackSize);

  // Save it.
  memcpy(Epilogue, info.Bytes, sizeof(info));
  return Epilogue + sizeof(info);
}

// Handles an unwind operation code UWOP_PUSH_NONVOL and returns an address
// where to use next in Epilogue, or returns nullptr in case of error.
ALLOC_TEXT(PAGED, FnparsepInterpretPushNonVolOp)
_Use_decl_annotations_ EXTERN_C static UCHAR *FnparsepInterpretPushNonVolOp(
    UCHAR OpInfo, UCHAR *Epilogue) {
  PAGED_CODE();

  const auto info = FnparsepGetPushNonVolOpInfo(OpInfo);
  if (info.Size == 0) {
    return nullptr;
  }
  memcpy(Epilogue, &info.Bytes, info.Size);
  return Epilogue + info.Size;
}

// Converts Operation Info code to corresponding byte code.
// http://msdn.microsoft.com/en-us/library/ck9asaa9.aspx
ALLOC_TEXT(PAGED, FnparsepGetPushNonVolOpInfo)
_Use_decl_annotations_ EXTERN_C static EpilogueOpcodeInfo
FnparsepGetPushNonVolOpInfo(UCHAR OpInfo) {
  PAGED_CODE();

  switch (OpInfo) {
    // clang-format off
    case 0:  return { EpilogueOpcode::PopRax, sizeof(EpilogueOpcode::PopRax), };
    case 1:  return { EpilogueOpcode::PopRcx, sizeof(EpilogueOpcode::PopRcx), };
    case 2:  return { EpilogueOpcode::PopRdx, sizeof(EpilogueOpcode::PopRdx), };
    case 3:  return { EpilogueOpcode::PopRbx, sizeof(EpilogueOpcode::PopRbx), };
    case 4:  return { EpilogueOpcode::PopRsp, sizeof(EpilogueOpcode::PopRsp), };
    case 5:  return { EpilogueOpcode::PopRbp, sizeof(EpilogueOpcode::PopRbp), };
    case 6:  return { EpilogueOpcode::PopRsi, sizeof(EpilogueOpcode::PopRsi), };
    case 7:  return { EpilogueOpcode::PopRdi, sizeof(EpilogueOpcode::PopRdi), };
    case 8:  return { EpilogueOpcode::PopR8,  sizeof(EpilogueOpcode::PopR8), };
    case 9:  return { EpilogueOpcode::PopR9,  sizeof(EpilogueOpcode::PopR9), };
    case 10: return { EpilogueOpcode::PopR10, sizeof(EpilogueOpcode::PopR10), };
    case 11: return { EpilogueOpcode::PopR11, sizeof(EpilogueOpcode::PopR11), };
    case 12: return { EpilogueOpcode::PopR12, sizeof(EpilogueOpcode::PopR12), };
    case 13: return { EpilogueOpcode::PopR13, sizeof(EpilogueOpcode::PopR13), };
    case 14: return { EpilogueOpcode::PopR14, sizeof(EpilogueOpcode::PopR14), };
    case 15: return { EpilogueOpcode::PopR15, sizeof(EpilogueOpcode::PopR15), };
    default: return {};
      // clang-format on
  }
}
