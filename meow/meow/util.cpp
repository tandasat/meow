// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements utility functions.
//
#include "stdafx.h"
#include "util.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Masks to select bits used for getting PTEs.
#ifdef _AMD64_
static const auto UTILP_PXI_MASK = 0x1ff;
static const auto UTILP_PPI_MASK = 0x3ffff;
static const auto UTILP_PDI_MASK = 0x7ffffff;
static const auto UTILP_PTI_MASK = 0xfffffffff;
#else
static const auto UTILP_PDI_MASK = 0xffffffff;
static const auto UTILP_PTI_MASK = 0xffffffff;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct WINDOWS_RT_PTE {
  ULONG NoExecute : 1;
  ULONG Present : 1;
  ULONG Unknown1 : 5;
  ULONG Writable : 1;
  ULONG Unknown2 : 4;
  ULONG PageFrameNumber : 20;
};
static_assert(sizeof(WINDOWS_RT_PTE) == 4, "Size check");

struct WINDOWS_AMD64_PTE {
  ULONG64 Present : 1;
  ULONG64 Write : 1;
  ULONG64 Owner : 1;
  ULONG64 WriteThrough : 1;
  ULONG64 CacheDisable : 1;
  ULONG64 Accessed : 1;
  ULONG64 Dirty : 1;
  ULONG64 LargePage : 1;
  ULONG64 Global : 1;
  ULONG64 CopyOnWrite : 1;
  ULONG64 Prototype : 1;
  ULONG64 reserved0 : 1;
  ULONG64 PageFrameNumber : 28;
  ULONG64 reserved1 : 12;
  ULONG64 SoftwareWsIndex : 11;
  ULONG64 NoExecute : 1;
};
static_assert(sizeof(WINDOWS_AMD64_PTE) == 8, "Size check");

#ifdef _AMD64_
using HARDWARE_PTE = WINDOWS_AMD64_PTE;
#else
using HARDWARE_PTE = WINDOWS_RT_PTE;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C void NTAPI KeSweepIcacheRange(_In_ BOOLEAN AllProcessors,
                                       _In_ PVOID BaseAddress,
                                       _In_ ULONG Length);

#ifdef _AMD64_
EXTERN_C static HARDWARE_PTE *UtilpAddressToPxe(_In_ const void *Address);

EXTERN_C static HARDWARE_PTE *UtilpAddressToPpe(_In_ const void *Address);
#endif

EXTERN_C static HARDWARE_PTE *UtilpAddressToPde(_In_ const void *Address);

EXTERN_C static HARDWARE_PTE *UtilpAddressToPte(_In_ const void *Address);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// memmem().
_Use_decl_annotations_ EXTERN_C void *UtilMemMem(const void *SearchBase,
                                                 SIZE_T SearchSize,
                                                 const void *Pattern,
                                                 SIZE_T PatternSize) {
  if (PatternSize > SearchSize) {
    return nullptr;
  }
  auto searchBase = static_cast<const char *>(SearchBase);
  for (size_t i = 0; i <= SearchSize - PatternSize; i++) {
    if (!memcmp(Pattern, &searchBase[i], PatternSize)) {
      return const_cast<char *>(&searchBase[i]);
    }
  }
  return nullptr;
}

// Return true if the given address is accessible. It does not prevent a race
// condition.
_Use_decl_annotations_ EXTERN_C bool UtilIsAccessibleAddress(
    const void *Address) {
#ifdef _AMD64_
  const auto pxe = UtilpAddressToPxe(Address);
  const auto ppe = UtilpAddressToPpe(Address);
  const auto pde = UtilpAddressToPde(Address);
  const auto pte = UtilpAddressToPte(Address);
  if ((!pxe->Present) || (!ppe->Present) || (!pde->Present) ||
      (!pde->LargePage && (!pte || !pte->Present))) {
    return false;
  }
#else
  const auto pde = UtilpAddressToPde(Address);
  const auto pte = UtilpAddressToPte(Address);
  if (!pde->Present || !pde->PageFrameNumber || !pte->Present ||
      !pte->PageFrameNumber) {
    return false;
  }
#endif
  return true;
}

// Returns true if the given address is executable. It does not prevent a race
// condition.
_Use_decl_annotations_ EXTERN_C bool UtilIsExecutableAddress(
    const void *Address) {
  if (!UtilIsAccessibleAddress(Address)) {
    return false;
  }

#ifdef _AMD64_
  const auto pde = UtilpAddressToPde(Address);
  const auto pte = UtilpAddressToPte(Address);
  if (pde->NoExecute || (!pde->LargePage && (!pte || pte->NoExecute))) {
    return false;
  }
#else
  const auto pte = UtilpAddressToPte(Address);
  if (pte->NoExecute) {
    return false;
  }
#endif
  return true;
}

// Sleep()
ALLOC_TEXT(PAGED, UtilSleep)
_Use_decl_annotations_ EXTERN_C NTSTATUS UtilSleep(LONG Millisecond) {
  PAGED_CODE();
  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000 * Millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

// Loads pointer size value from the registry.
ALLOC_TEXT(PAGED, UtilLoadPointerVaule)
_Use_decl_annotations_ EXTERN_C NTSTATUS
UtilLoadPointerVaule(const wchar_t *Key, const wchar_t *Value, void **Data) {
  PAGED_CODE();

  UNICODE_STRING path = {};
  RtlInitUnicodeString(&path, Key);
  OBJECT_ATTRIBUTES oa = RTL_INIT_OBJECT_ATTRIBUTES(
      &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

  // Open the registry
  HANDLE keyNaked = nullptr;
  auto status = ZwOpenKey(&keyNaked, KEY_READ, &oa);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto key =
      std::experimental::make_unique_resource(std::move(keyNaked), &::ZwClose);

  UNICODE_STRING valueName = {};
  RtlInitUnicodeString(&valueName, Value);

  // Read value
  ULONG resultLength = 0;
  UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(void *)] = {};
  status = ZwQueryValueKey(key.get(), &valueName, KeyValuePartialInformation,
                           buffer, sizeof(buffer), &resultLength);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Error if it is not an expected type or not a pointer size.
  ULONG expectedRegType = (IsX64()) ? REG_QWORD : REG_DWORD;
  auto data = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION *>(buffer);
  if (data->Type != expectedRegType || data->DataLength != sizeof(void *)) {
    return STATUS_DATA_NOT_ACCEPTED;
  }

  *Data = *reinterpret_cast<void **>(data->Data);
  return status;
}

// Invalidates an instruction cache for the specified region.
_Use_decl_annotations_ EXTERN_C void UtilInvalidateInstructionCache(
    void *BaseAddress, SIZE_T Length) {
#ifdef _AMD64_
  UNREFERENCED_PARAMETER(BaseAddress);
  UNREFERENCED_PARAMETER(Length);
  __faststorefence();
#else
  KeSweepIcacheRange(TRUE, BaseAddress, Length);
#endif
}

// Does memcpy safely even if Destination is a read only region.
_Use_decl_annotations_ EXTERN_C NTSTATUS UtilForceMemCpy(void *Destination,
                                                         const void *Source,
                                                         SIZE_T Length) {
  auto mdl = std::experimental::make_unique_resource(
      IoAllocateMdl(Destination, static_cast<ULONG>(Length), FALSE, FALSE,
                    nullptr),
      &IoFreeMdl);
  if (!mdl) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  MmBuildMdlForNonPagedPool(mdl.get());

#pragma warning(push)
#pragma warning(disable : 28145)
  //
  // Following MmMapLockedPagesSpecifyCache() call causes bug check in case
  // you are using Driver Verifier. The reason is explained as follows:
  //
  // A driver must not try to create more than one system-address-space
  // mapping for an MDL. Additionally, because an MDL that is built by the
  // MmBuildMdlForNonPagedPool routine is already mapped to the system
  // address space, a driver must not try to map this MDL into the system
  // address space again by using the MmMapLockedPagesSpecifyCache routine.
  // -- MSDN
  //
  // This flag modification hacks Driver Verifier's check and prevent leading
  // bug check.
  //
  mdl.get()->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
  mdl.get()->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

  auto writableDest = MmMapLockedPagesSpecifyCache(
      mdl.get(), KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
  if (!writableDest) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  memcpy(writableDest, Source, Length);
  MmUnmapLockedPages(writableDest, mdl.get());
  return STATUS_SUCCESS;
}

// Converts a function pointer to a function address.
_Use_decl_annotations_ EXTERN_C UCHAR *UtilFpToData(FARPROC FunctionPointer) {
  if (IsX64()) {
    return reinterpret_cast<UCHAR *>(FunctionPointer);
  } else {
    return reinterpret_cast<UCHAR *>(
        reinterpret_cast<ULONG_PTR>(FunctionPointer) & ~1);
  }
}

// Converts a function address to a function pointer.
_Use_decl_annotations_ EXTERN_C FARPROC UtilDataToFp(UCHAR *FunctionAddress) {
  if (IsX64()) {
    return reinterpret_cast<FARPROC>(FunctionAddress);
  } else {
    return reinterpret_cast<FARPROC>(
        reinterpret_cast<ULONG_PTR>(FunctionAddress) | 1);
  }
}

/*
Virtual Address Interpretation For Handling PTEs

-- On x64
Sign extension                     16 bits
Page map level 4 selector           9 bits
Page directory pointer selector     9 bits
Page directory selector             9 bits
Page table selector                 9 bits
Byte within page                   12 bits
11111111 11111111 11111000 10000000 00000011 01010011 00001010 00011000
^^^^^^^^ ^^^^^^^^ ~~~~~~~~ ~^^^^^^^ ^^~~~~~~ ~~~^^^^^ ^^^^~~~~ ~~~~~~~~
Sign extension    PML4      PDPT      PD        PT        Offset

-- On ARM
Page directory selector            10 bits
Page table selector                10 bits
Byte within page                   12 bits
10000011 01100000 11010010 01110101
~~~~~~~~ ~~^^^^^^ ^^^^~~~~ ~~~~~~~~
PD         PT         Offset

*/

#ifdef _AMD64_

// Return an address of PXE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPxe(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PXI_SHIFT) & UTILP_PXI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PXE_BASE + offset);
}

// Return an address of PPE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPpe(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PPI_SHIFT) & UTILP_PPI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PPE_BASE + offset);
}

#endif

// Return an address of PDE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPde(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PDI_SHIFT) & UTILP_PDI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PDE_BASE + offset);
}

// Return an address of PTE
_Use_decl_annotations_ EXTERN_C static HARDWARE_PTE *UtilpAddressToPte(
    const void *Address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(Address);
  const auto index = (addr >> PTI_SHIFT) & UTILP_PTI_MASK;
  const auto offset = index * sizeof(HARDWARE_PTE);
  return reinterpret_cast<HARDWARE_PTE *>(PTE_BASE + offset);
}
