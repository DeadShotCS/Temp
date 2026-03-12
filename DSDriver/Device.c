/*
    Universal Driver: DSDriver

    Device.c:
        Holds the driver routines

    Logs:
        02/26/2025: Initial Driver Created
*/

#include "Device.h"

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;

    DbgPrint("[*] DSDriver Called!\n");

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\DSDriver");

    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("[*] DrvUnsupported: This function is not supported!\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("[*] DrvRead: Not implemented yet!\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("[*] DrvWrite: Not implemented yet!\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] DrvCreate Called !\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("[*] DrvClose Called!\n");
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // Variables to use for IOCTL information and output
    PIO_STACK_LOCATION IrpStack;                  // Pointer to current stack location
    NTSTATUS           NtStatus = STATUS_SUCCESS; // Assume success
    ULONG              InBufLength;               // Input buffer length
    ULONG              OutBufLength;              // Output buffer length
    PCHAR              InBuf, OutBuf;             // pointer to Input and output buffer (Warnings are due to uninitailzed since buffers are in different Irp Locations for each method)
    PCHAR              Data = "This String is from Device Driver !!!";
    size_t             DataLen = strlen(Data) + 1; // Length of data including null
    PMDL               Mdl = NULL;
    PCHAR              Buffer = NULL;

    // These parameters are used in methods other than IOCTL_SIOCTL_METHOD_BUFFERED
    UNREFERENCED_PARAMETER(Mdl);
    UNREFERENCED_PARAMETER(Buffer);

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    InBufLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutBufLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (!InBufLength || !OutBufLength)
    {
        NtStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //

    switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case TEST_IOCTL_BUFFERED:

        DbgPrint("Called IOCTL_SIOCTL_METHOD_BUFFERED\n");
        PrintIrpInfo(Irp);

        // Input buffer and output buffer is same in this case, read the content of the buffer before writing to it
        InBuf = Irp->AssociatedIrp.SystemBuffer;
        OutBuf = Irp->AssociatedIrp.SystemBuffer;

        // Read the data from the buffer
        DbgPrint("\tData from User :");

        // We are using the following function to print characters instead DebugPrint with %s format because we string we get may or
        // may not be null terminated.
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        // Write to the buffer over-writes the input buffer content
        RtlCopyBytes(OutBuf, Data, OutBufLength);

        DbgPrint(("\tData to User : "));
        PrintChars(OutBuf, DataLen);

        // Assign the length of the data copied to IoStatus.Information of the Irp and complete the Irp.
        Irp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        // When the Irp is completed the content of the SystemBuffer is copied to the User output buffer and the SystemBuffer is
        // is freed.

        Open_Close_File();
        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //
        NtStatus = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("ERROR: unrecognized IOCTL %x\n",
            IrpStack->Parameters.DeviceIoControl.IoControlCode);
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = NtStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

VOID
PrintIrpInfo(PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer);
    DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        IrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        IrpStack->Parameters.DeviceIoControl.InputBufferLength);
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
    return;
}