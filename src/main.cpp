#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0500 
#include <Windows.h>
#include <stdio.h>
#include <ctype.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>

extern "C" {
#include "../lua.h"
#include "../lauxlib.h"
#include "../lualib.h"
}

#ifndef SECURITY_MANDATORY_HIGH_RID
	#define SECURITY_MANDATORY_UNTRUSTED_RID            (0x00000000L)
	#define SECURITY_MANDATORY_LOW_RID                  (0x00001000L)
	#define SECURITY_MANDATORY_MEDIUM_RID               (0x00002000L)
	#define SECURITY_MANDATORY_HIGH_RID                 (0x00003000L)
	#define SECURITY_MANDATORY_SYSTEM_RID               (0x00004000L)
	#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID    (0x00005000L)
#endif

#ifndef TokenIntegrityLevel
	#define TokenIntegrityLevel ((TOKEN_INFORMATION_CLASS)25)
#endif

/*#ifndef TOKEN_MANDATORY_LABEL
	typedef struct  
	{
		SID_AND_ATTRIBUTES Label;
	} TOKEN_MANDATORY_LABEL;
#endif*/

typedef BOOL (WINAPI *defCreateProcessWithTokenW)
		(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
 

// Writes Integration Level of the process with the given ID into pu32_ProcessIL
// returns Win32 API error or 0 if succeeded
DWORD GetProcessIL(DWORD u32_PID, DWORD* pu32_ProcessIL)
{
	*pu32_ProcessIL = 0;
	
	HANDLE h_Process   = 0;
	HANDLE h_Token     = 0;
	DWORD  u32_Size    = 0;
	BYTE*  pu8_Count   = 0;
	DWORD* pu32_ProcIL = 0;
	TOKEN_MANDATORY_LABEL* pk_Label = 0;
 
	h_Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, u32_PID);
	if (!h_Process)
		goto _CleanUp;
 
	if (!OpenProcessToken(h_Process, TOKEN_QUERY, &h_Token))
		goto _CleanUp;
				
	if (!GetTokenInformation(h_Token, TokenIntegrityLevel, NULL, 0, &u32_Size) &&
		 GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto _CleanUp;
						
	pk_Label = (TOKEN_MANDATORY_LABEL*) HeapAlloc(GetProcessHeap(), 0, u32_Size);
	if (!pk_Label)
		goto _CleanUp;
 
	if (!GetTokenInformation(h_Token, TokenIntegrityLevel, pk_Label, u32_Size, &u32_Size))
		goto _CleanUp;
 
	pu8_Count = GetSidSubAuthorityCount(pk_Label->Label.Sid);
	if (!pu8_Count)
		goto _CleanUp;
					
	pu32_ProcIL = GetSidSubAuthority(pk_Label->Label.Sid, *pu8_Count-1);
	if (!pu32_ProcIL)
		goto _CleanUp;
 
	*pu32_ProcessIL = *pu32_ProcIL;
	SetLastError(ERROR_SUCCESS);
 
	_CleanUp:
	DWORD u32_Error = GetLastError();
	if (pk_Label)  HeapFree(GetProcessHeap(), 0, pk_Label);
	if (h_Token)   CloseHandle(h_Token);
	if (h_Process) CloseHandle(h_Process);
	return u32_Error;
}
 
// Creates a new process u16_Path with the integration level of the Explorer process (MEDIUM IL)
// If you need this function in a service you must replace FindWindow() with another API to find Explorer process
// The parent process of the new process will be svchost.exe if this EXE was run "As Administrator"
// returns Win32 API error or 0 if succeeded
DWORD CreateProcessMediumIL(WCHAR* u16_Path, WCHAR* u16_CmdLine)
{
	HANDLE h_Process = 0;
	HANDLE h_Token   = 0;
	HANDLE h_Token2  = 0;
	PROCESS_INFORMATION k_ProcInfo    = {0};
	STARTUPINFOW        k_StartupInfo = {0};
 
	BOOL b_UseToken = FALSE;
 
	// Detect Windows Vista, 2008, Windows 7 and higher
	if (GetProcAddress(GetModuleHandleA("Kernel32"), "GetProductInfo"))
	{
		DWORD u32_CurIL;
		DWORD u32_Err = GetProcessIL(GetCurrentProcessId(), &u32_CurIL);
		if (u32_Err)
			return u32_Err;
 
		if (u32_CurIL > SECURITY_MANDATORY_MEDIUM_RID)
			b_UseToken = TRUE;
	}
 
	// Create the process normally (before Windows Vista or if current process runs with a medium IL)
	if (!b_UseToken)
	{
		if (!CreateProcessW(u16_Path, u16_CmdLine, 0, 0, FALSE, 0, 0, 0, &k_StartupInfo, &k_ProcInfo))
			return GetLastError();
 
		CloseHandle(k_ProcInfo.hThread);
		CloseHandle(k_ProcInfo.hProcess); 
		return ERROR_SUCCESS;
	}
 
	defCreateProcessWithTokenW f_CreateProcessWithTokenW = 
		(defCreateProcessWithTokenW) GetProcAddress(GetModuleHandleA("Advapi32"), "CreateProcessWithTokenW");
 
	if (!f_CreateProcessWithTokenW) // This will never happen on Vista!
		return ERROR_INVALID_FUNCTION; 
	
	HWND h_Progman = ::GetShellWindow();
 
	DWORD u32_ExplorerPID = 0;		
	GetWindowThreadProcessId(h_Progman, &u32_ExplorerPID);
 
	// ATTENTION:
	// If UAC is turned OFF all processes run with SECURITY_MANDATORY_HIGH_RID, also Explorer!
	// But this does not matter because to start the new process without UAC no elevation is required.
	h_Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, u32_ExplorerPID);
	if (!h_Process)
		goto _CleanUp;
 
	if (!OpenProcessToken(h_Process, TOKEN_DUPLICATE, &h_Token))
		goto _CleanUp;
 
	if (!DuplicateTokenEx(h_Token, TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &h_Token2))
		goto _CleanUp;
 
	if (!f_CreateProcessWithTokenW(h_Token2, 0, u16_Path, u16_CmdLine, 0, 0, 0, &k_StartupInfo, &k_ProcInfo))
		goto _CleanUp;
 
	SetLastError(ERROR_SUCCESS);
 
	_CleanUp:
	DWORD u32_Error = GetLastError();
	if (h_Token)   CloseHandle(h_Token);
	if (h_Token2)  CloseHandle(h_Token2);
	if (h_Process) CloseHandle(h_Process);
	CloseHandle(k_ProcInfo.hThread);
	CloseHandle(k_ProcInfo.hProcess); 
	return u32_Error;
}

static int l_SpawnProcess(lua_State* L)
{
	const char* path = lua_tostring(L, 1);
	wchar_t* pathW = new wchar_t[strlen(path) + 1];
	MultiByteToWideChar(CP_UTF8, 0, path, -1, pathW, strlen(path) + 1);
	const char* cmdLine = lua_tostring(L, 2);
	if (cmdLine) {
		wchar_t* cmdLineW = new wchar_t[strlen(cmdLine) + 1];
		MultiByteToWideChar(CP_UTF8, 0, cmdLine, -1, cmdLineW, strlen(cmdLine) + 1);
		CreateProcessMediumIL(pathW, cmdLineW);
		delete cmdLineW;
	} else {
		CreateProcessMediumIL(pathW, NULL);
	}
	delete pathW;
	return 0;
}

// From lua.c
static int traceback (lua_State *L) {
  if (!lua_isstring(L, 1))  /* 'message' not a string? */
    return 1;  /* keep it intact */
  lua_getfield(L, LUA_GLOBALSINDEX, "debug");
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    return 1;
  }
  lua_getfield(L, -1, "traceback");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  lua_pushvalue(L, 1);  /* pass error message */
  lua_pushinteger(L, 2);  /* skip this function and traceback */
  lua_call(L, 2, 1);  /* call debug.traceback */
  return 1;
}

static char* AllocString(const char* st)
{
	if (st == NULL) {
		return NULL;
	}
	size_t aslen = strlen(st) + 1;
	char* al = new char[aslen];
	strcpy_s(al, aslen, st);
	return al;
}

class args_c {
private:
	char* argBuf;
public:
	int		argc;
	char*	argv[256];

	args_c::args_c(char* in)
	{
		argc = 0;
		memset(argv, 0, sizeof(char*) * 256);
		argBuf = AllocString(in);
		char* ptr = argBuf;
		while (*ptr) {
			if (isspace(*ptr)) {
				ptr++;
			} else if (*ptr == '"') {
				argv[argc++] = ++ptr;
				while (*ptr && *ptr != '"') ptr++;
				if (*ptr) *(ptr++) = 0;
			} else {
				argv[argc++] = ptr++;
				while (*ptr && !isspace(*ptr)) ptr++;
				if (*ptr) *(ptr++) = 0;
			}
		}
	}
	args_c::~args_c()
	{
		delete argBuf;
	}
};

bool consoleInit = false;
void InitConsole(const char* title)
{
	if (consoleInit) {
		return;
	}
	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	SetConsoleTitle(title);
	consoleInit = true;
}

int __stdcall WinMain(HINSTANCE hInst, HINSTANCE hInstP, LPSTR CmdLine, int ShowCmd)
{
	int status = 0;

	args_c args(GetCommandLine());

	InitConsole(args.argv[1]);

	if (args.argc < 2) {
		printf("No input file specified.\n");
		status = 1;
		goto end;
	}

	FILE* f = fopen(args.argv[1], "r");
	if ( !f ) {
		printf("Error: input file '%s' not found.\n", args.argv[1]);
		status = 1;
		goto end;
	}

	lua_State* L = luaL_newstate();
	lua_pushcfunction(L, traceback);
	lua_pushvalue(L, -1);
	lua_setfield(L, LUA_REGISTRYINDEX, "traceback");
	luaL_openlibs(L);
	lua_pushcfunction(L, l_SpawnProcess);
	lua_setglobal(L, "SpawnProcess");
 	status = luaL_loadfile(L, args.argv[1]);
	if (status) {
		printf("Error loading script: %s\n", lua_tostring(L, -1));
		lua_close(L);
		goto end;
	}

	int scrArgc = args.argc - 1;
	char** scrArgv = new char*[scrArgc];
	for (int a = 0; a < scrArgc; a++) {
		const char* arg = args.argv[a + 1];
		if (a > 0 && strlen(arg) > 3 && isupper(arg[0]) && arg[1] == ':' && arg[2] == '\\') {
			scrArgv[a] = new char[512];
			GetLongPathName(arg, scrArgv[a], 512);
		} else {
			scrArgv[a] = AllocString(arg);
		}
	}
	for (int i = 1; i < scrArgc; i++) {
		lua_pushstring(L, scrArgv[i]);
	}
	lua_createtable(L, scrArgc - 1, 1);
	for (int i = 0; i < scrArgc; i++) {
		lua_pushstring(L, scrArgv[i]);
		lua_rawseti(L, -2, i);
		delete scrArgv[i];
	}
	delete scrArgv;
	lua_setglobal(L, "arg");

	status = lua_pcall(L, scrArgc - 1, 0, 1);
	if (status) {
		printf("Error running script:\n%s\n", lua_tostring(L, -1));
	}
	lua_close(L);

end:
	if (status) {
		system("pause");
	}
	return status;
}