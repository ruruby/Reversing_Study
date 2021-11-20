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

	//���μ��� ã��
	dwPID = FindProcessID(DEF_PROC_NAME);
	if (dwPID == 0xFFFFFFFF)
	{
		printf("There is no <%s> process!\n", DEF_PROC_NAME);
		return 1;
	}

	//dll �����ϱ�
	InjectDLL(dwPID, DEF_DLL_PATH);
	return 0;
}

DWORD FindProcessID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	//�ý����� ������ ���α�
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	//���μ��� ã��
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


	// 1. pePID�� �̿��Ͽ� ��� ���μ���(notepad.exe)�� HANDLE�� ���Ѵ�
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
		return FALSE;

	// 2. ��� ���μ���(notepad.exe) �޸𸮿� szDllName ũ�⸸ŭ �޸𸮸� �Ҵ��Ѵ�
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	// 3. �Ҵ� ���� �޸𸮿� myhack.dll ��θ� ����
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);

	// 4. LoadLibraryA() API �ּҸ� ���Ѵ�
	hMod = GetModuelHandle("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");

	// 5. notepad.exe ���μ����� �����带 �����Ѵ�
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHand(hProcess);

	return TRUE;
}
