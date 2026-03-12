/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include "Device.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);


EXTERN_C_END
