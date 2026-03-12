#include "Ioctl.h"

DWORD
TestIoctl(FunctionArguments Arguments)
{
	char  OutputBuffer[1000];
	char  InputBuffer[1000];
	ULONG BytesReturned;
	BOOL  Result;
	HANDLE Handle = *(Arguments.DriverHandle);
	//
	// Performing METHOD_BUFFERED
	//
	StringCbCopyA(InputBuffer, sizeof(InputBuffer), "This String is from User Application; using METHOD_BUFFERED");

	printf("\n[TestIoctl] Calling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));

	Result = DeviceIoControl(Handle,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&BytesReturned,
		NULL);

	if (!Result)
	{
		printf("[TestIoctl] Error in DeviceIoControl : %d\n", GetLastError());
		return GetLastError();
	}
	printf("[TestIoctl] OutBuffer (%d): %s\n", BytesReturned, OutputBuffer);

	return FUNCTION_SUCCESS;
}

DWORD 
OpenDevice(HANDLE* hWnd, const wchar_t* devicePath) {
	*hWnd = CreateFile(devicePath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ |
			FILE_SHARE_WRITE,
			NULL, /// lpSecurityAttirbutes
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL |
			FILE_FLAG_OVERLAPPED,
			NULL); /// lpTemplateFile
	if (*hWnd != INVALID_HANDLE_VALUE)
		return FUNCTION_SUCCESS;
	else {
		return GetLastError();
	}
}

DWORD 
CloseDevice(HANDLE* hWnd) {
	if (INVALID_HANDLE_VALUE != *hWnd) {
		printf("[CloseDevice] Closing open device handle.\n");
		if (!CloseHandle(*hWnd)) { return FUNCTION_SUCCESS; }
		else { return GetLastError(); }
	}
	else {
		printf("[CloseDevice] Device handle isn't valid to close.\n");
		return FUNCTION_SUCCESS;
	}
}