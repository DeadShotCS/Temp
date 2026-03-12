#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "Helpers.h"

/*----------------------------------------
	Driver Functions
----------------------------------------*/
VOID
DrvUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

/*----------------------------------------
    IOCTL(s)
----------------------------------------*/
// IOCTL Codes and Its meanings
#define IOCTL_TEST 0x1 // In case of testing

// Device type           -- in the "User Defined" range."
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.

#define TEST_IOCTL_BUFFERED \
    CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// In this type of transfer,  the I/O manager allocates a system buffer
// large enough to accommodatethe User input buffer, sets the buffer address
// in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
// into the SystemBuffer. For the user output buffer, the  I/O manager
// probes to see whether the virtual address is readable in the callers
// access mode, locks the pages in memory and passes the pointer to
// MDL describing the buffer in Irp->MdlAddress.
//
#define IOCTL_SIOCTL_METHOD_IN_DIRECT \
    CTL_CODE(SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

//
// In this type of transfer, the I/O manager allocates a system buffer
// large enough to accommodate the User input buffer, sets the buffer address
// in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
// into the SystemBuffer. For the output buffer, the I/O manager
// probes to see whether the virtual address is writable in the callers
// access mode, locks the pages in memory and passes the pointer to MDL
// describing the buffer in Irp->MdlAddress.
//
#define IOCTL_SIOCTL_METHOD_OUT_DIRECT \
    CTL_CODE(SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

//
// In this method the I/O manager allocates a buffer large enough to
// to accommodate larger of the user input buffer and output buffer,
// assigns the address to Irp->AssociatedIrp.SystemBuffer, and
// copies the content of the user input buffer into this SystemBuffer
//
#define IOCTL_SIOCTL_METHOD_BUFFERED \
    CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// In this type of transfer the I/O manager assigns the user input
// to Type3InputBuffer and the output buffer to UserBuffer of the Irp.
// The I/O manager doesn't copy or map the buffers to the kernel
// buffers. Nor does it perform any validation of user buffer's address
// range.
//
#define IOCTL_SIOCTL_METHOD_NEITHER \
    CTL_CODE(SIOCTL_TYPE, 0x903, METHOD_NEITHER, FILE_ANY_ACCESS)

/*----------------------------------------
    Helper Functions
----------------------------------------*/
VOID
PrintIrpInfo(PIRP Irp);