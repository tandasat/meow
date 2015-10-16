// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver and initializes other
// components in this module.
//
#include "stdafx.h"
#include "log.h"
#include "dispg.h"
#include "../Common/meow_ioctl.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

#if DBG
static const auto MEOWP_LOG_LEVEL = LOG_PUT_LEVEL_DEBUG;
#else
static const auto MEOWP_LOG_LEVEL = LOG_PUT_LEVEL_INFO;
#endif

static UNICODE_STRING MEOWP_DEVICE_NAME =
    RTL_CONSTANT_STRING(L"\\Device\\meow");
static UNICODE_STRING MEOWP_DOS_DEVICE_NAME =
    RTL_CONSTANT_STRING(L"\\DosDevices\\meow");

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C DRIVER_INITIALIZE DriverEntry;

EXTERN_C static NTSTATUS MeowpInitialization(_In_ PDRIVER_OBJECT DriverObject);

EXTERN_C static DRIVER_UNLOAD MeowpDriverUnload;

EXTERN_C static void MeowpTermination(_In_ PDRIVER_OBJECT DriverObject);

EXTERN_C static __drv_dispatchType(IRP_MJ_CREATE) __drv_dispatchType(
    IRP_MJ_CLOSE) DRIVER_DISPATCH MeowpIrpOpenAndCloseHandler;

EXTERN_C static __drv_dispatchType(IRP_MJ_SHUTDOWN)
    DRIVER_DISPATCH MeowpIrpShutdownHandler;

EXTERN_C static __drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
    DRIVER_DISPATCH MeowpIrpIoControlHandler;

EXTERN_C static NTSTATUS MeowpIrpIoControlDispatcher(
    _In_ ULONG IoControlCode, _In_ void *SystemBuffer,
    _In_ ULONG InputBufferLength, _In_ ULONG OutputBufferLength,
    _In_ ULONG_PTR *ResultInformation);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

ALLOC_TEXT(INIT, DriverEntry)
_Use_decl_annotations_ EXTERN_C NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  PAGED_CODE();
  auto status = STATUS_UNSUCCESSFUL;

  DBG_BREAK();

  // Initialize driver environment.
  status = MeowpInitialization(DriverObject);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedMeowpTermination = std::experimental::make_scope_exit(
      [DriverObject]() { MeowpTermination(DriverObject); });

  // Initialize a log system with enabling file output.
  status = LogInitialization(MEOWP_LOG_LEVEL, L"\\SystemRoot\\meow.log");
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedLogTermination = std::experimental::make_scope_exit(
      [DriverObject]() { LogTermination(); });

  // Initialize a DisarmPatchGuard component.
  status = DispgInitialization(RegistryPath);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedDispgTermination =
      std::experimental::make_scope_exit(&DispgTermination);

  scopedDispgTermination.release();
  scopedLogTermination.release();
  scopedMeowpTermination.release();
  return status;
}

// Initialize basic driver environment.
ALLOC_TEXT(INIT, MeowpInitialization)
_Use_decl_annotations_ EXTERN_C static NTSTATUS MeowpInitialization(
    PDRIVER_OBJECT DriverObject) {
  PAGED_CODE();

#pragma warning(push)
#pragma warning(disable : 28175)
  DriverObject->DriverUnload = MeowpDriverUnload;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = MeowpIrpOpenAndCloseHandler;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = MeowpIrpOpenAndCloseHandler;
  DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = MeowpIrpShutdownHandler;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MeowpIrpIoControlHandler;
#pragma warning(pop)

  auto status = AuxKlibInitialize();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Allow only an administrator open this device.
  status = IoCreateDeviceSecure(DriverObject, 0, &MEOWP_DEVICE_NAME,
                                MEOW_DEVICE_CODE, FILE_DEVICE_SECURE_OPEN,
                                FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, nullptr,
                                &DriverObject->DeviceObject);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedIoDeleteDevice = std::experimental::make_scope_exit(
      [DriverObject]() { IoDeleteDevice(DriverObject->DeviceObject); });

  status = IoCreateSymbolicLink(&MEOWP_DOS_DEVICE_NAME, &MEOWP_DEVICE_NAME);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedIoDeleteSymbolicLink = std::experimental::make_scope_exit(
      []() { IoDeleteSymbolicLink(&MEOWP_DOS_DEVICE_NAME); });

  scopedIoDeleteDevice.release();
  scopedIoDeleteSymbolicLink.release();
  return status;
}

// Unloading the driver. Close and restore everything.
ALLOC_TEXT(PAGED, MeowpDriverUnload)
_Use_decl_annotations_ EXTERN_C static void MeowpDriverUnload(
    PDRIVER_OBJECT DriverObject) {
  PAGED_CODE();

  LOG_DEBUG("Being terminated.");
  DBG_BREAK();

  DispgTermination();
  LogTermination();
  MeowpTermination(DriverObject);
}

// Terminate driver environment.
ALLOC_TEXT(PAGED, MeowpTermination)
_Use_decl_annotations_ EXTERN_C static void MeowpTermination(
    PDRIVER_OBJECT DriverObject) {
  PAGED_CODE();

  IoDeleteSymbolicLink(&MEOWP_DOS_DEVICE_NAME);
  IoDeleteDevice(DriverObject->DeviceObject);
}

ALLOC_TEXT(PAGED, MeowpIrpOpenAndCloseHandler)
_Use_decl_annotations_ EXTERN_C static NTSTATUS MeowpIrpOpenAndCloseHandler(
    PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DeviceObject);

  const auto status = STATUS_SUCCESS;

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return status;
}

// A shut down handler for flushing a log file.
ALLOC_TEXT(PAGED, MeowpIrpShutdownHandler)
_Use_decl_annotations_ EXTERN_C static NTSTATUS MeowpIrpShutdownHandler(
    PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DeviceObject);

  const auto status = STATUS_SUCCESS;

  LOG_DEBUG("Shutdown handler is being called.");
  LogIrpShutdownHandler();

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return status;
}

// An IOCTL handler.
ALLOC_TEXT(PAGED, MeowpIrpIoControlHandler)
_Use_decl_annotations_ EXTERN_C static NTSTATUS MeowpIrpIoControlHandler(
    PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DeviceObject);

  auto status = STATUS_INVALID_DEVICE_REQUEST;
  auto ioStackIrp = IoGetCurrentIrpStackLocation(Irp);
  ULONG_PTR resultInformation = 0;

  if (ioStackIrp) {
    auto systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    auto ioControlCode = ioStackIrp->Parameters.DeviceIoControl.IoControlCode;
    auto inputBufferLength =
        ioStackIrp->Parameters.DeviceIoControl.InputBufferLength;
    auto outputBufferLength =
        ioStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
    status = MeowpIrpIoControlDispatcher(ioControlCode, systemBuffer,
                                         inputBufferLength, outputBufferLength,
                                         &resultInformation);
  }

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = resultInformation;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return status;
}

// An actual dispatcher for IOCTLs.
ALLOC_TEXT(PAGED, MeowpIrpIoControlDispatcher)
_Use_decl_annotations_ EXTERN_C static NTSTATUS MeowpIrpIoControlDispatcher(
    ULONG IoControlCode, void *SystemBuffer, ULONG InputBufferLength,
    ULONG OutputBufferLength, ULONG_PTR *ResultInformation) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(SystemBuffer);
  UNREFERENCED_PARAMETER(InputBufferLength);
  UNREFERENCED_PARAMETER(OutputBufferLength);
  UNREFERENCED_PARAMETER(ResultInformation);

  auto status = STATUS_SUCCESS;
  switch (IoControlCode) {
    case MEOW_IOCTL_DISARM:
      status = DispgDisablePatchGuard();
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
  }
  if (NT_SUCCESS(status)) {
    LOG_DEBUG("IOCTL 0x%08X returned 0x%08X", IoControlCode, status);
  } else {
    LOG_WARN("IOCTL 0x%08X returned 0x%08X", IoControlCode, status);
  }
  return status;
}
