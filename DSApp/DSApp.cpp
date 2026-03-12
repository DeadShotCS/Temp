/*
	Universal Driver: DSDriver

	DSApp.cpp:
		Holds main startup logic for user app

	Logs:
		02/26/2025: Initial Driver Created
*/

#include "DSApp.h"
#include <windows.h>
#include <winternl.h>

// Command(s)
std::list<UserSpaceAppCommand> AllCommands = {
	UserSpaceAppCommand("Test Command For a Buffered IOCTL", "-test", "", (DWORD)TEST_IOCTL_BUFFERED, true, TestIoctl),
	UserSpaceAppCommand("List All Other Commands", "-help", "", NULL, false, printCommandsAvailable),
};

int main(int argc, char* argv[])
{
	NTSTATUS	status = 0;
	ULONG64		in_address;

	DWORD			retVal;
	FunctionArguments Arguments{};
	CommandFunc		CommandFunction = NULL;
	BOOL			DriverRequired	= false;
	BOOL			DriverLoaded	= false;



	// Needed if we load the Driver and Open the device for IOCTLs. This will free itself at the end.
	HANDLE hWnd[1] = { (HANDLE)INVALID_HANDLE_VALUE };

	for (int i = 1; i < argc; i++) {
		// Argument Searching 
		//--------------------------------------------------------------------------
		if (::_stricmp(argv[i], "-a") == 0) {
			if (argc == i + 1) {
				printf("[*] Error: Address missing with '-a' input\n");
				return -1;
			}
			else {
				in_address = hexStringToNum(argv[i + 1]);
				i++;
			}
		}

		// Function Searching
		// This is somewhat unoptimized, but I don't really care for my use case here
		//--------------------------------------------------------------------------
		for (UserSpaceAppCommand Command : AllCommands) {
			if (::_stricmp(argv[i], Command.commandIdentifier) == 0) {
				printf("Command found %s\n", argv[i]);
				DriverRequired = Command.DriverRequired;
				CommandFunction = (CommandFunc)Command.Function;

				if (Command.IOCTL) {
					Arguments.DriverHandle = hWnd;
					Arguments.DriverIOCTL = Command.IOCTL;
				}
			}
		}
	}

	// We should have a valid CommandFunction now, otherwise fail
	if (!CommandFunction) {
		printf("[*] No function specified.\n");
		printCommandsAvailable(Arguments);
		goto exit;
	}

	// Make sure that the first thing we do after argument checking
	// is to start the driver if required
	if (DriverRequired) {
		// 1. Loading the associated driver
		status = LoadNTDriver((WCHAR*)L"DSDriver", (WCHAR*)L".\\DSDriver.sys");
		if (status == FUNCTION_SUCCESS) {
			DriverLoaded = true;
			printf("[*] Driver Loaded Successfully.\n");
		}
		else { 
			printf("[*] Driver failed to load with ErrorCode: %s (%d).\n", GetLastErrorAsString(status).c_str(), status);
			goto exit; 
		}

		// 2. Open the device handle
		status = OpenDevice(hWnd, L"\\\\.\\DSDriver");
		if (status == FUNCTION_SUCCESS) {
			printf("[*] Device Open Successfully.\n");
		}
		else {
			printf("[*] Device failed to open with ErrorCode: %s (%d).\n", GetLastErrorAsString(status).c_str(), status);
			goto exit;
		}
	}

	// Both the Driver and Device object are set up
	retVal = CommandFunction(Arguments);
	if (retVal == FUNCTION_SUCCESS) {
		printf("[*] Function Success: %s (%d).\n", GetLastErrorAsString(retVal).c_str(), retVal);
	}
	else {
		printf("[*] Function Error: %s (%d).\n", GetLastErrorAsString(retVal).c_str(), retVal);
	}

	system("pause");
	

exit:
	if (DriverLoaded) { UnloadNTDriver((WCHAR*)L"DSDriver"); }
	if (*hWnd != (HANDLE)INVALID_HANDLE_VALUE) { CloseDevice(hWnd); }
	return status;
}