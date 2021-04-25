#pragma once
#define PIPE_NAME L"PipeServerImpersonate"
#define THREAD_TIMEOUT 20000
BOOL EnablePriv(HANDLE, LPCTSTR);
PSID BuildEveryoneSid();
BOOL AddTheAceDesktop(HDESK, PSID);
BOOL AddTheAceWindowStation(HWINSTA, PSID);
void Usage();
void PipeServerImpersonate(wchar_t* commandline, wchar_t* pipe_placeholder, wchar_t* arguments);
int CreatePipeServer(wchar_t*, bool endless);
