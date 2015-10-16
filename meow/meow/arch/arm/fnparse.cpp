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

// http://msdn.microsoft.com/en-us/library/dn743843.aspx
union XDATA_HEADER {
  ULONG Value;
  struct {
    ULONG FunctionLength : 18;  // [ 0-17]
    ULONG Vers : 2;             // [18-19]
    ULONG X : 1;                // [20]
    ULONG E : 1;                // [21]
    ULONG F : 1;                // [22]
    ULONG EpilogueCount : 5;    // [23-27]
    ULONG CodeWords : 4;        // [28-31]
  } Fields;
};
static_assert(sizeof(XDATA_HEADER) == 4, "Size check");

union XDATA_HEADER_EX {
  ULONG Value;
  struct {
    ULONG ExtendedEpilogueCount : 16;  // [ 0-15]
    ULONG ExtendedCodeWords : 8;       // [16-23]
    ULONG Reserved : 8;                // [24-31]
  } Fields;
};
static_assert(sizeof(XDATA_HEADER_EX) == 4, "Size check");

union XDATA_EPILOGUE_SCOPE {
  ULONG Value;
  struct {
    ULONG EpilogueStartOffset : 18;  // [ 0-17]
    ULONG Res : 2;                   // [18-19]
    ULONG Condition : 4;             // [20-23]
    ULONG EpilogueStartIndex : 8;    // [24-31]
  } Fields;
};
static_assert(sizeof(XDATA_EPILOGUE_SCOPE) == 4, "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C IMAGE_RUNTIME_FUNCTION_ENTRY *NTAPI
RtlLookupFunctionEntry(_In_ PVOID ControlPc, _Out_ PVOID *ImageBase,
                       _Inout_opt_ struct UNWIND_HISTORY_TABLE *HistoryTable);

EXTERN_C static EpilogueInfo FnparsepParsePackedUnwindData(
    _In_ UCHAR *FunctionAddress,
    _In_ const IMAGE_RUNTIME_FUNCTION_ENTRY *Entry);

EXTERN_C static EpilogueInfo FnparsepParseXdataRecords(
    _In_ UCHAR *FunctionAddress, _In_ const ULONG *Entry);

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

// Returns a function length in bytes, or 0 if failed.
ALLOC_TEXT(PAGED, FnparseGetFunctionLength)
_Use_decl_annotations_ EXTERN_C SIZE_T
FnparseGetFunctionLength(UCHAR *FunctionAddress) {
  PAGED_CODE();

  UCHAR *base = nullptr;
  auto entry = FnparseLookupFunctionEntry(
      UtilDataToFp(reinterpret_cast<UCHAR *>(FunctionAddress)),
      reinterpret_cast<void **>(&base));
  if (!entry) {
    return 0;
  }

  if (entry->Flag) {
    return entry->FunctionLength * 2;
  }

  auto xdata = reinterpret_cast<const ULONG *>(base + entry->UnwindData);
  auto xdataHeader = reinterpret_cast<const XDATA_HEADER *>(&xdata[0]);
  return xdataHeader->Fields.FunctionLength * 2;
}

// Retrieves the given function's epilogue address(es), epilogue length and
// stack size, or returns empty information when it failed to solve any of them.
// This function is not meant to cover all functions. It is merely designed to
// be able to handle a good enough range of functions for this project's
// purpose.
//
// Here is an example of where it returns as an epilogue address:
//
// On ARM:
//  MOV     R0, R9
//  ADD     SP, SP, #0x5C       ; this address will be returned.
//  POP.W   { R4 - R11, PC }
//
ALLOC_TEXT(PAGED, FnparseGetEpilogueInfo)
_Use_decl_annotations_ EXTERN_C EpilogueInfo
FnparseGetEpilogueInfo(UCHAR *FunctionAddress) {
  PAGED_CODE();

  LOG_DEBUG("FunctionAddress = %p", FunctionAddress);

  UCHAR *base = nullptr;
  auto entry = FnparseLookupFunctionEntry(UtilDataToFp(FunctionAddress),
                                          reinterpret_cast<void **>(&base));
  if (!entry) {
    return {};
  }

  if (entry->Flag) {
    // A Packed Unwind Data structure
    return FnparsepParsePackedUnwindData(FunctionAddress, entry);
  } else {
    // Parse a .xdata entry.
    auto xdata = reinterpret_cast<ULONG *>(base + entry->UnwindData);
    return FnparsepParseXdataRecords(FunctionAddress, xdata);
  }
}

// Returns an EpilogueInfo with parsing a Packed Unwind Data structure, or empty
// object when it failed.
ALLOC_TEXT(PAGED, FnparsepParsePackedUnwindData)
_Use_decl_annotations_ EXTERN_C static EpilogueInfo
FnparsepParsePackedUnwindData(UCHAR *FunctionAddress,
                              const IMAGE_RUNTIME_FUNCTION_ENTRY *Entry) {
  PAGED_CODE();

  static const auto EXPECTED_EPILOGUE_LENGTH = 6ul;

  // Only supports the basic packed unwind data format
  if (Entry->Flag != 1) {
    return {};
  }

  // Only supports returning via pop {pc}
  if (Entry->Ret != 0) {
    return {};
  }

  // Only supports no "homing" functions
  if (Entry->H != 0) {
    return {};
  }

  // Only supports saving integer registers
  if (Entry->R != 0) {
    return {};
  }

  auto numberOfSavedRegs = Entry->Reg + 1;  // + 1 because of r4

  // Do no unwind stack for the lr register as it is going to read contents of
  // stack corresponding to lr.
  // if (entry->L == 1) {
  //  numberOfSavedRegs++;  // + lr
  //}

  if (Entry->C == 1) {
    numberOfSavedRegs++;  // + r11
  }

  // Only supports directly encoded stack adjust
  if (Entry->StackAdjust >= 0x3f4) {
    return {};
  }

  // Guesswork to get an epilogue address
  //
  // 0045AFE8 20 46       MOV             R0, R4         ; epilogueAddress -2
  // 0045AFEA 0D B0       ADD             SP, SP, #0x34  ; epilogueAddress
  // 0045AFEC BD E8 F0 8F POP.W{ R4 - R11,PC }
  // 0045AFF0                                            ; functionEndAddress
  auto functionEndAddress = FunctionAddress + Entry->FunctionLength * 2;
  auto epilogueAddress = functionEndAddress - EXPECTED_EPILOGUE_LENGTH;
  if (*(epilogueAddress - 2 + 1) != 0x46)  // make sure it is MOV R0, Rx
  {
    return {};
  }
  auto unwinedStackSize = Entry->StackAdjust * 4 + numberOfSavedRegs * 4;
  LOG_DEBUG("EpilogueAddress = %p", epilogueAddress);
  LOG_DEBUG("EpilogueSize = %08X, UnwinedStackSize = %08X",
            EXPECTED_EPILOGUE_LENGTH, unwinedStackSize);
  return {
      EXPECTED_EPILOGUE_LENGTH,
      unwinedStackSize,
      {
          epilogueAddress,
      },
  };
}

// Returns an EpilogueInfo with parsing .pdata and .xdata, or empty object when
// it failed.
ALLOC_TEXT(PAGED, FnparsepParseXdataRecords)
_Use_decl_annotations_ EXTERN_C static EpilogueInfo FnparsepParseXdataRecords(
    UCHAR *FunctionAddress, const ULONG *Xdata) {
  PAGED_CODE();

  // The first byte is XDATA_HEADER.
  auto xdataHeader = reinterpret_cast<const XDATA_HEADER *>(&Xdata[0]);
  if (xdataHeader->Fields.E) {
    // A single epilogue is packed into the header. Unexpected.
    return {};
  }

  // XDATA_HEADER_EX may exist in the second byte. XDATA_HEADER_EX is not used,
  // so determine where to look at next.
  const bool hasExtendedHeader = (xdataHeader->Fields.CodeWords == 0 &&
                                  xdataHeader->Fields.EpilogueCount == 0);

  // XDATA_EPILOGUE_SCOPE(s) after XDATA_HEADER or XDATA_HEADER_EX.
  auto xdataEpilogue = reinterpret_cast<const XDATA_EPILOGUE_SCOPE *>(
      &Xdata[(hasExtendedHeader) ? 2 : 1]);

  // Get a number of epilogues
  auto epilogueCount =
      (hasExtendedHeader)
          ? reinterpret_cast<const XDATA_HEADER_EX *>(&Xdata[1])
                ->Fields.ExtendedEpilogueCount
          : xdataHeader->Fields.EpilogueCount;

  // Get addresses of epilogues
  UCHAR *epilogueAddresses[FNPARSEP_MAX_SUPPORTED_EPILOGUE_NUMBER] = {};
  for (auto i = 0ul; i < epilogueCount; ++i) {
    epilogueAddresses[i] =
        FunctionAddress + xdataEpilogue[i].Fields.EpilogueStartOffset * 2;
  }

  // A sequence of unwind codes after XDATA_EPILOGUE_SCOPE(s).
  auto unwindCodes =
      reinterpret_cast<const UCHAR *>(&xdataEpilogue[epilogueCount]);

  // Parse all unwind opcodes and calculate an epilogue size and an unwind
  // stack size.
  ULONG epilogueSize = 0;
  ULONG ignoreSizeForAddress = 0;
  ULONG unwinedStackSize = 0;
  for (auto i = 0ul;; ++i) {
    const auto code = unwindCodes[i];
    LOG_DEBUG("Unwind Code = %02X", code);

    if (0x00 <= code && code <= 0x7f) {
      // add   sp,sp,#X
      auto x = (code & 0x7f) * 4ul;  // X is (Code & 0x7F) * 4.
      unwinedStackSize += x;         // Add it to unwind stack size.
      epilogueSize += 2;             // Opcode size is 2.
      ignoreSizeForAddress = 2;      // Updates an ignorable instruction size.
      LOG_DEBUG("SP = %08X, UW = %08X", x, unwinedStackSize);

    } else if (0xd8 <= code && code <= 0xdf) {
      // pop   {r4-rX,lr}
      auto x = (code & 0x03) + 8ul;  // X is (Code & 0x03) + 8.
      x = x - 4 + 1;                 // Get number of registers (ignore lr).
      x *= 4;                        // Convert to bytes.
      unwinedStackSize += x;         // Add it to unwind stack size.
      epilogueSize += 4;             // Opcode size is 4.
      ignoreSizeForAddress = 4;      // Updates an ignorable instruction size.
      LOG_DEBUG("SP = %08X, UW = %08X", x, unwinedStackSize);

    } else if (0xfb <= code && code <= 0xfc) {
      // nop

    } else if (0xfd <= code && code <= 0xff) {
      // end
      break;

    } else {
      // Do not support others yet. Too tedious.
      return {};
    }
  }

  // Do not subtract a length of the first epilogue instruction
  // (ignoreSizeForAddress) since we want the address of the beginning of
  // epilogue.
  for (auto &epilogueAddress : epilogueAddresses) {
    if (!epilogueAddress) {
      break;
    }
    epilogueAddress -= (epilogueSize - ignoreSizeForAddress);
    LOG_DEBUG("EpilogueAddress = %p", epilogueAddress);
  }

  LOG_DEBUG("EpilogueSize = %08X, UnwinedStackSize = %08X", epilogueSize,
            unwinedStackSize);

  EpilogueInfo epilogueInfo = {
      epilogueSize, unwinedStackSize,
  };
  memcpy(epilogueInfo.EpilogueAddresses, epilogueAddresses,
         sizeof(epilogueAddresses));
  static_assert(
      sizeof(epilogueInfo.EpilogueAddresses) == sizeof(epilogueAddresses),
      "Size check");
  return epilogueInfo;
}
