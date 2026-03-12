#pragma once
#include <Windows.h>
#include <list>

/*----------------------------------------
	Globals
----------------------------------------*/

#define FUNCTION_SUCCESS 0
#define GENERAL_FUNCTION_FAILURE -1

/*----------------------------------------
	Functions Functions
----------------------------------------*/

struct FunctionArguments {
	HANDLE* DriverHandle;
	DWORD	DriverIOCTL;
};

// Currently this is forcing at least one argument, doesn't seem like I can use a variadic function for this type of call
typedef DWORD(*CommandFunc)(FunctionArguments Arguments);

/*----------------------------------------
	Command Object
----------------------------------------*/
class UserSpaceAppCommand {
public:
	char	commandName[256] = "";
	char	commandIdentifier[32] = "";
	char	ExampleStringCont[64] = "";
	DWORD	IOCTL = NULL;
	BOOL	DriverRequired = false;
	void* Function = NULL;

	UserSpaceAppCommand(const char* CN, const char* CI, const char* ESC, DWORD I, BOOL DR, void* Func) {
		strcpy_s(commandName, CN);
		strcpy_s(commandIdentifier, CI);
		strcpy_s(ExampleStringCont, ESC);
		IOCTL = I;
		DriverRequired = DR;
		Function = Func;
	}
	void _printCommand() {
		printf("UserSpaceAppCommand:\n");
		printf("\tcommandName: %s\n", commandName);
		printf("\tcommandIdentifier: %s\n", commandIdentifier);
		printf("\texampleCommand: %s %s %s\n", ".\\DSApp.exe", commandIdentifier, ExampleStringCont);
		printf("\tDriverRequired: %d\n", DriverRequired);
		printf("\tIOCTL: %u\n", IOCTL);
	}

};