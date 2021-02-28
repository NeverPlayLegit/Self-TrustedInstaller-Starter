
#include <iostream>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <UserEnv.h>

#pragma comment(lib, "Userenv.lib")

/**
Checks whether the application in running in elevated state
**/
bool isElevated() {
	bool res = false;
	HANDLE token = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		TOKEN_ELEVATION elevation;
		DWORD size = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
			res = elevation.TokenIsElevated;
		}
	}
	if (token) {
		CloseHandle(token);
	}
	return res;
}

/**
Installs and starts the service that will start our application with TrustedInstaller
As far as i know, only services can start applications as TI
**/
void installAndStartService() {
	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);

	char pathWithParams[MAX_PATH + 32];
	sprintf_s(pathWithParams, MAX_PATH + 32, "%s --service", path);

	SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	SC_HANDLE service = OpenService(serviceManager, "TestService", GENERIC_EXECUTE);

	if (service == NULL) {
		service = CreateService(
			serviceManager,
			"TestService",
			"TestService",
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			pathWithParams,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL);
	}

	StartService(service, 0, NULL);

	CloseServiceHandle(service);
	CloseServiceHandle(serviceManager);
}

/**
Deletes our elevation service
**/
void deleteService() {
	SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	SC_HANDLE service = OpenService(serviceManager, "TestService", DELETE);

	if (service) {
		DeleteService(service);
	}

	CloseServiceHandle(service);
	CloseServiceHandle(serviceManager);
}

/**
Checks whether our application is already running with system rights (so TrustedInstaller)
**/
bool isSystem() {
	char username[256];
	DWORD usernameLen = 256;
	GetUserName(username, &usernameLen);
	return strncmp(username, "SYSTEM", 6) == 0;
}

/**
Starts our application as TrustedInstaller by duplicating the winlogons process token
(winlogon in the current session)
**/
bool startAppAsTI() {
	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	HANDLE winlogonHandle = 0;
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			DWORD winlogonSessionId;
			ProcessIdToSessionId(entry.th32ProcessID, &winlogonSessionId);

			if (strcmp(entry.szExeFile, "winlogon.exe") == 0 && winlogonSessionId == WTSGetActiveConsoleSessionId()) {
				winlogonHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
			}
		}
	}

	CloseHandle(snapshot);

	if (!winlogonHandle)
		return false;
		

	HANDLE winlogonToken;
	if (!OpenProcessToken(winlogonHandle, TOKEN_ALL_ACCESS_P, &winlogonToken)) {
		CloseHandle(winlogonHandle);
		return false;
	}

	SECURITY_ATTRIBUTES se = { 0 };
	se.nLength = sizeof(SECURITY_ATTRIBUTES);
	se.bInheritHandle = TRUE;
	se.lpSecurityDescriptor = NULL;

	HANDLE newToken;
	if (!DuplicateTokenEx(winlogonToken, MAXIMUM_ALLOWED, &se, SecurityIdentification, TokenPrimary, &newToken)) {
		CloseHandle(winlogonHandle);
		CloseHandle(winlogonToken);
		return false;
	}

	DWORD sessionId = WTSGetActiveConsoleSessionId();
	SetTokenInformation(newToken, TokenSessionId, &sessionId, sizeof(sessionId));

	DWORD uiAccess = 1;
	SetTokenInformation(newToken, TokenUIAccess, &uiAccess, sizeof(uiAccess));

	STARTUPINFO startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.wShowWindow = SW_SHOWDEFAULT;
	startupInfo.lpDesktop = const_cast<LPSTR>("Winsta0\\Default");

	LPVOID env = NULL;
	DWORD flags = 48;
	if (CreateEnvironmentBlock(&env, newToken, TRUE)) flags |= 0x400;

	PROCESS_INFORMATION pi;
	if (!CreateProcessAsUser(newToken, path, (LPSTR)path, &se, &se, FALSE, flags, env, NULL, &startupInfo, &pi)) {
		CloseHandle(winlogonHandle);
		CloseHandle(winlogonToken);
		CloseHandle(newToken);
		return false;
	}

	return true;
}

/**
Tries to start our application elevated as administrator so that we can deploy the service
**/
bool startAppAsAdmin() {
	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	SHELLEXECUTEINFO shexecInfo = { 0 };
	shexecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	shexecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shexecInfo.hwnd = NULL;
	shexecInfo.lpVerb = "runas";
	shexecInfo.lpFile = path;
	shexecInfo.lpParameters = NULL;
	shexecInfo.lpDirectory = NULL;
	shexecInfo.nShow = SW_SHOW;
	shexecInfo.hInstApp = NULL;
	ShellExecuteEx(&shexecInfo);
	
	bool res = shexecInfo.hProcess != 0;

	CloseHandle(shexecInfo.hProcess);
	
	return res;
}

int main(int argc, char* argv[]) {
	if (argc == 2) {
		if (strcmp(argv[1], "--service") == 0) {
			startAppAsTI();
			deleteService();
		}
	}
	else {
		if (isSystem()) {
			MessageBox(NULL, "Running as System", "Error", MB_OK);
		}
		else {
			if (isElevated()) {
				installAndStartService();
			}
			else {
				if (!startAppAsAdmin()) {
					MessageBox(NULL, "Running as normal user", "Error", MB_OK);
				}
			}
		}
	}
}
