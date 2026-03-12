#include "Driver.h"


DWORD 
LoadNTDriver(WCHAR* lpszDriverName, WCHAR* lpszDriverPath)
{
	WCHAR szDriverImagePath[256];

	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);
	DWORD bRet = FUNCTION_SUCCESS;

	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;

	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hServiceMgr == NULL)
	{
		bRet = GetLastError();
		printf("[LoadNtDriver] OpenSCManager() Failed %d !\n", bRet);
		goto BeforeLeave;
	}
	else
	{
		printf("[LoadNtDriver] OpenSCManager() Success !\n");
	}


	hServiceDDK = CreateService(hServiceMgr,	// hSCManager
					lpszDriverName,				// LpServiceName
					lpszDriverName,				// LpDisplayName
					SERVICE_ALL_ACCESS,			// dwDesiredAccess
					SERVICE_KERNEL_DRIVER,		// dwServiceType
					SERVICE_DEMAND_START,		// dwStartType
					SERVICE_ERROR_IGNORE,		// dwErrorControl
					szDriverImagePath,			// lpBinaryPathName
					NULL,						// lpLoadOrderGroup
					NULL,
					NULL,
					NULL,
					NULL);

	DWORD dwRtn;

	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			printf("[LoadNtDriver] CreateService() Failed %d ! \n", dwRtn);
			bRet = dwRtn;
			goto BeforeLeave;
		}
		else
		{
			printf("[LoadNtDriver] CreateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
		}


		hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
		if (hServiceDDK == NULL)
		{
			dwRtn = GetLastError();
			printf("[LoadNtDriver] OpenService() Failed %d ! \n", dwRtn);
			bRet = dwRtn;
			goto BeforeLeave;
		}
		else
		{
			printf("[LoadNtDriver] OpenService() Success ! \n");
		}
	}
	else
	{
		printf("[LoadNtDriver] CrateService() Success ! \n");
	}


	bRet = StartService(hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("[LoadNtDriver] StartService() Failed %d ! \n", dwRtn);
			bRet = dwRtn;
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				printf("[LoadNtDriver] StartService() Failed ERROR_IO_PENDING ! \n");
				bRet = dwRtn;
				goto BeforeLeave;
			}
			else
			{
				printf("[LoadNtDriver] StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = FUNCTION_SUCCESS;
				goto BeforeLeave;
			}
		}
	}
	bRet = FUNCTION_SUCCESS;

BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}


DWORD 
UnloadNTDriver(WCHAR* szSvrName)
{
	DWORD bRet = FUNCTION_SUCCESS;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;
	SERVICE_STATUS SvrSta;

	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		bRet = GetLastError();
		printf("[UnloadNtDriver] OpenSCManager() Failed %d ! \n", bRet);
		goto BeforeLeave;
	}
	else
	{
		printf("[UnloadNtDriver] OpenSCManager() Success ! \n");
	}

	hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

	if (hServiceDDK == NULL)
	{
		bRet = GetLastError();
		printf("[UnloadNtDriver] OpenService() Failed %d ! \n", bRet);
		goto BeforeLeave;
	}
	else
	{
		printf("[UnloadNtDriver] OpenService() Success ! \n");
	}

	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
	{
		bRet = GetLastError();
		printf("[UnloadNtDriver] ControlService() Failed %d !\n", bRet);
		goto BeforeLeave;
	}
	else
	{
		printf("[UnloadNtDriver] ControlService() Success !\n");
	}
 
	if (!DeleteService(hServiceDDK))
	{
		bRet = GetLastError();
		printf("[UnloadNtDriver] DeleteService() Failed %d !\n", bRet);
		goto BeforeLeave;
	}
	else
	{
		printf("[UnloadNtDriver] DeleteService() Success !\n");
	}
	bRet = FUNCTION_SUCCESS;


BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}