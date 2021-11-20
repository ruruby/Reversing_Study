#include "stdio.h"
#include "windows.h"
#include "tlhelp32.h"

#define DEF_PROC_NAME "notepad.exe"
#define DEF_DLL_PATH "c:\\myhack.dll"

DWORD FindProcessID(LPCTSTR szProcessName);
BOOL InjectDLL(DWORD dwPID, LPCTSTR szDLLName);

int main(int argc, char* argv[])
{
	DWORD dwPID = 0xFFFFFFFF;

	//프로세스 찾기
	dwPID = FindProcessID(DEF_PROC_NAME);
	if (dwPID == 0xFFFFFFFF)
	{
		printf("There is no <%s> process!\n", DEF_PROC_NAME);
		return 1;
	}

	//dll 주입하기
	InjectDLL(dwPID, DEF_DLL_PATH);
	return 0;
}

DWORD FindProcessID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	//시스템의 스냅샷 찍어두기
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	//프로세스 찾기
	Process32First(hSnapShot, &pe);
	do
	{
		if (!_stricmp(szProcessName, pe.szExeFile))
		{
			dwPID = pe.th32ProcessID;
			break;
		}
	}

	while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return dwPID;
}

BOOL InjectDLL(DWORD dwPID, LPCTSTR szDllName)
{
	HANDLE hProcess, hThread;
	HMODULE hMod;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = lstrlen(szDllName) + 1;
	LPTHREAD_START_ROUTINE pThreadProc;


	// 1. pePID를 이용하여 대상 프로세스(notepad.exe)의 HANDLE을 구한다
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
		return FALSE;

	// 2. 대상 프로세스(notepad.exe) 메모리에 szDllName 크기만큼 메모리를 할당한다
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	// 3. 할당 받은 메모리에 myhack.dll 경로를 쓴다
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);

	// 4. LoadLibraryA() API 주소를 구한다
	hMod = GetModuelHandle("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");

	// 5. notepad.exe 프로세스에 스레드를 실행한다
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHand(hProcess);

	return TRUE;
}
