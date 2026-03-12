#pragma once

#include "DSApp.h"

extern std::list<UserSpaceAppCommand> AllCommands;

void
printFile() {
	std::ifstream f("ascii.txt");
	if (f.is_open())
		std::cout << f.rdbuf();
	printf("\n\n");
}

ULONG64
hexStringToNum(char* Input) {
	return strtoull(Input, NULL, 16);
}


std::string 
GetLastErrorAsString(DWORD errorMessageID) {
    LPVOID message_buffer;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorMessageID,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&message_buffer,
        0,
        nullptr);

    std::string error_message(CW2A((LPCTSTR)message_buffer));
    error_message.erase(std::remove(error_message.begin(), error_message.end(), '\n'), error_message.end());
    error_message.erase(std::remove(error_message.begin(), error_message.end(), '\r'), error_message.end());
    LocalFree(message_buffer);

    return error_message;
}