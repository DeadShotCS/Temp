/*
    Universal Driver: DSDriver

    Helpers.c:
        Holds helpers for indirect calls, asm, etc

    Logs:
        02/26/2025: Initial Driver Created
*/

#include "Helpers.h"

VOID
Open_Close_File() {
    HANDLE handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING path;
    UNICODE_STRING pathfunc;
    OBJECT_ATTRIBUTES objAttr;

    wchar_t pathbuf[] = L"\\DosDevices\\C:\\Users\\Josh\\CreatedFile.txt";

    path.Buffer = pathbuf;
    path.MaximumLength = sizeof(pathbuf);
    path.Length = sizeof(pathbuf) - sizeof(wchar_t);

    RtlInitUnicodeString(&pathfunc, L"\\DosDevices\\C:\\Users\\Josh\\CreatedFile.txt");

    DbgPrint("pathfunc: BUF->%lx, LEN->%lx, MAX->%lx\n", pathfunc.Buffer, pathfunc.Length, pathfunc.MaximumLength);
    DbgPrint("path: BUF->%lx, LEN->%lx, MAX->%lx\n", path.Buffer, path.Length, path.MaximumLength);

    InitializeObjectAttributes(&objAttr, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ntstatus = ZwCreateFile(
        &handle,
        GENERIC_WRITE,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    DbgPrint("ZwCreateFile: %lx\n", ntstatus);
    if (ntstatus == STATUS_SUCCESS)
        ZwClose(handle);
}

VOID
PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars)
{
    PAGED_CODE();

    char buf[512];
    size_t curCount = 0;

    if (CountChars)
    {
        while (CountChars--)
        {
            if (curCount == 511) {
                break;
            }
            if (*BufferAddress > 31 && *BufferAddress != 127)
            {
                //KdPrint(("%c", *BufferAddress));
                buf[curCount] = *BufferAddress;
            }
            else
            {
                //KdPrint(("."));
                buf[curCount] = '.';
            }
            BufferAddress++;
            curCount++;
        }
        buf[curCount] = '\0';
        DbgPrint("PrintChars: %s\n", buf);
        //KdPrint(("\n"));
    }
    return;
}