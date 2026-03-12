#pragma once

#include "DSApp.h"
#include "CommonStructs.h"

extern std::list<UserSpaceAppCommand> AllCommands;

DWORD
printCommandsAvailable(FunctionArguments Arguments) {
	printf("[*] Commands Available:\n");
	for (UserSpaceAppCommand Command : AllCommands) {
		Command._printCommand();
	}
	return FUNCTION_SUCCESS;
}