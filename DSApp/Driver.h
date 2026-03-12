#pragma once
#include <windows.h> 
#include <winsvc.h> 
#include <conio.h> 
#include <stdio.h>
#include "DSApp.h"

/*----------------------------------------
    Loader Functions
----------------------------------------*/
DWORD
LoadNTDriver(WCHAR* lpszDriverName, WCHAR* lpszDriverPath);

DWORD
UnloadNTDriver(WCHAR* szSvrName);