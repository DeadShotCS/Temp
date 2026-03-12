/*
    Universal Driver: DSDriver

    Driver.c:
        Main driver entry point

    Logs:
        02/26/2025: Initial Driver Created
*/


#include "Driver.h"

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS       NtStatus = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;

    DbgPrint("[*] DSDriverEntry Called.\n");

    RtlInitUnicodeString(&DriverName, L"\\Device\\DSDriver");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\DSDriver");

    NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

    if (NtStatus == STATUS_SUCCESS)
    {
        for (int Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
            DriverObject->MajorFunction[Index] = DrvUnsupported;

        DbgPrint("[*] Setting Devices major functions.\n");
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctlDispatcher;

        DriverObject->MajorFunction[IRP_MJ_READ] = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = DrvWrite;

        DriverObject->DriverUnload = DrvUnload;

        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    else
        DbgPrint("[*] There were some errors in creating device.\n");

    AsmTest();

    return NtStatus;
}