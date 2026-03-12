#pragma once

#include <Windows.h>
#include <winternl.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include <bitset>
#include <array>
#include <string>
#include <fstream>
#include <cstdint>
#include <strsafe.h>
#include <list>
#include <atlstr.h>
#include <stdexcept>

#include "CommonStructs.h"
#include "Ioctl.h"
#include "Driver.h"

int
main(int argc, char* argv[]);

/*
	NOTICE:
		The Requirements for functions are as listed
		1. They must be defined in the AllCommands list (Top of DSAPP.cpp)
		2. They must have required arguments in FunctionArguments struct
		3. They must self validate argument being set. Struct arguments will be NULL at start
*/

// Func printCommandsAvailable(VOID)
// SUMMARY: Will print all commands in the AllCommands list
DWORD
printCommandsAvailable(FunctionArguments Arguments);

/*----------------------------------------
	Helper Functions
----------------------------------------*/

void
printFile();

ULONG64
hexStringToNum(char* Input);

std::string
GetLastErrorAsString(DWORD errorMessageID);

