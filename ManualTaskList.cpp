// ManualTaskList.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// 
// 
// 
// 
// 
// From Ogden

/*
	NOTES:
		* printError to be replace by our log statements. It's purely for seeing what is happening right now.
		* Outputs will be changed to our own output once able.
		* Will also add flags for setting once able.
		* 
		* 
Help getting system token to read all data, from: https://0x00-0x00.github.io/research/2018/10/21/Windows-API-And-Impersonation-Part-2.html
*/

#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <synchapi.h>
#include <wtsapi32.h>

// Forward declarations:
BOOL GetProcessList();
BOOL ListProcessModules(DWORD dwPID);
BOOL ListProcessThreads(DWORD dwOwnerPID);
BOOL WriteProcessName(PROCESSENTRY32 pe32, HANDLE hFile);
BOOL WriteAndIncrementFile(HANDLE hFile, const TCHAR* DataBuffer, DWORD dwBytesToWrite);
BOOL WriteProcessSessionName(PROCESSENTRY32 pe32, HANDLE hFile);
BOOL WriteProcessSessionId(PROCESSENTRY32 pe32, HANDLE hFile);
BOOL WriteProcessID(PROCESSENTRY32 pe32, HANDLE hFile);
BOOL WriteProcessMemUsage(PROCESSENTRY32 pe32, HANDLE hFile);
void printError(TCHAR* msg);

// Globals:
TCHAR * filepath = (TCHAR *) TEXT("C:\\Users\\robgu\\OneDrive\\Documents\\AirForce\\90COS\\ManualTaskList\\testoutput.txt");
HANDLE hFile = NULL;
OVERLAPPED OverlappedIO;
const size_t maxCount = 1024;
const TCHAR* lpcwstrLineDivider = TEXT("\n\n");
DWORD dwLenLineDivider = wcsnlen_s(lpcwstrLineDivider, maxCount) * sizeof(WCHAR);
BOOL ImpersonateProcessToken(DWORD PID);
BOOL ResetProcessToken();
DWORD GetPIDToTryAndImpersonate();
void LpoverlappedCompletionRoutine(
	DWORD dwErrorCode,
	DWORD dwNumberOfBytesTransfered,
	LPOVERLAPPED lpOverlapped
){
	/*Empty routine, don't care to handle OverlappedIO right now...*/ 
}

int failcount = 0;
int goodcount = 0;

int main(void)
{
	// For testing, get the PID which the user wants to try for privelege escalation:
	DWORD pid = GetPIDToTryAndImpersonate();
	BOOL result = ImpersonateProcessToken(pid);
	result = GetProcessList();
	result = ResetProcessToken();

	printf("\nGood: %d \t Fail: %d", goodcount, failcount);

	//quick pause
	//Sleep(4000);
	
	if (TRUE == result) { 
		return 0; 
	}
	else { 
		return -1; 
	}


}

DWORD GetPIDToTryAndImpersonate() {
	DWORD ret = -1;

	/*
	PINPUT_RECORD inputRecord;
	DWORD dwEventsRead = 0;
	// HANDLE WINAPI GetStdHandle( _In_ DWORD nStdHandle);
	HANDLE hStdin = INVALID_HANDLE_VALUE;
	hStdin = GetStdHandle(STD_INPUT_HANDLE); // MSDN says no "CloseHandle()" required for this.
	if (INVALID_HANDLE_VALUE == hStdin) {
		printError((TCHAR*)TEXT("Couldn't get handle to standard input."));
		return ret;
	}


	
	//BOOL WINAPI ReadConsoleInputEx(
	//  _In_  HANDLE        hConsoleInput,
	//  _Out_ PINPUT_RECORD lpBuffer,
	//  _In_  DWORD         nLength,
	//  _Out_ LPDWORD       lpNumberOfEventsRead,
	//  _In_  USHORT        wFlags
	//);
	BOOL ret = ReadConsoleInput(
		hStdin,
		inputRecord,
		maxCount,
		&dwEventsRead
	);
	*/

	TCHAR lpwstrInput[maxCount] = { 0 };
	printf("Enter a PID to use for token impersonation: ");
	int result = wscanf_s( L"%s", (wchar_t*)lpwstrInput, (unsigned int) maxCount);
	if (1 != result) {
		printError((TCHAR*)TEXT("Error getting PID for token impersonation."));
		return ret;	// I'm violating the concept of single in-out points from routines...
	}

	result = _wtoi((wchar_t*) lpwstrInput);
	if (0 == result || INT_MAX == result || INT_MIN == result) {
		printError((TCHAR*)TEXT("Error reading given PID for token impersonation. (Or input was '0'.)"));
		return ret;
	}

	ret = result;

	printf("Read PID: %d\n", ret);
	return ret;
}

BOOL ImpersonateProcessToken(DWORD PID) {
	HANDLE hProcToImpersonateToken = INVALID_HANDLE_VALUE;
	HANDLE hDuplicatedTokenForUs = INVALID_HANDLE_VALUE;
	//HANDLE hCurrentThread = GetCurrentThread();
	HANDLE hSomeSystemProc = INVALID_HANDLE_VALUE;

	//HANDLE OpenProcess(
	//	[in] DWORD dwDesiredAccess,
	//	[in] BOOL  bInheritHandle,
	//	[in] DWORD dwProcessId
	//);
	HANDLE hProcToImpersonate = OpenProcess(
		// PROCESS_QUERY_INFORMATION,
		//| PROCESS_VM_READ,
		PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE,
		PID
	);

	if ( INVALID_HANDLE_VALUE == hProcToImpersonate || NULL == hProcToImpersonate) {
		printError((TCHAR*)TEXT("Error getting proc handle for given PID."));
		return FALSE;
	}

	//BOOL OpenProcessToken(
	//	[in] HANDLE  ProcessHandle,
	//	[in]  DWORD   DesiredAccess,
	//	[out] PHANDLE TokenHandle
	//	);
	BOOL result = OpenProcessToken(
		hProcToImpersonate,
		TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY,
		&hProcToImpersonateToken
	);

	if (INVALID_HANDLE_VALUE == hProcToImpersonateToken) {
		printError((TCHAR*)TEXT("Error getting proc token for given PID."));
		return FALSE;
	}

	//BOOL DuplicateToken(
	//	[in] HANDLE                       ExistingTokenHandle,
	//	[in]  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	//	[out] PHANDLE                      DuplicateTokenHandle
	//	);
	// SecurityImpersonation: The server process can impersonate the client security context on its local system only.
	_SECURITY_IMPERSONATION_LEVEL impersonationLevel = SecurityImpersonation;
	result = DuplicateToken(
		hProcToImpersonateToken,
		impersonationLevel,
		&hDuplicatedTokenForUs
	);

	if (INVALID_HANDLE_VALUE == hDuplicatedTokenForUs || FALSE == result) {
		printError((TCHAR*)TEXT("Error duplicating proc token for given PID: %d", PID));
		return FALSE;
	}

	result = SetThreadToken(
		NULL, //If Thread is NULL, the function assigns the impersonation token to the calling thread. (MSDN)
		hDuplicatedTokenForUs
	);

	if(FALSE == result) {
		printError((TCHAR*)TEXT("Error setting duplicated token for this thread.", PID));
		return FALSE;
	}

	// Now try to use the, hopefully, elevated privileges...
	hSomeSystemProc = OpenProcess(
		// PROCESS_QUERY_INFORMATION,
		//| PROCESS_VM_READ,
		PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE,
		180  // "registry", on my machine right now
	);

	if (INVALID_HANDLE_VALUE == hSomeSystemProc || NULL == hSomeSystemProc) {
		printError((TCHAR*)TEXT("Sad. I really hoped this would work."));
		return FALSE;
	}

	

	return TRUE;
}

BOOL ResetProcessToken() {
	// Reset the thread's token
	// If Token is NULL, the function causes the thread to stop using an impersonation token. (MSDN)
	BOOL result = SetThreadToken(
		NULL,
		NULL
	);
	if (FALSE == result) {
		printError((TCHAR*)TEXT("Error resetting or thread's token."));
		return FALSE;
	}
}

BOOL GetProcessList()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	//Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printError((TCHAR *) TEXT("CreateToolhelp32Snapshot (of processes)"));
		return FALSE;
	}

	//Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//Retrieve information about the first process and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printError((TCHAR *) TEXT("Process32First"));
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	hFile = CreateFile(
		filepath,                // name of the write
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_ALWAYS,             // create or open
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		printError((TCHAR*)TEXT("CreateFile"));
		_tprintf(TEXT("Terminal failure: Unable to open file \"%s\" for write.\n"), filepath);
		return FALSE;
	}


	

	//Now walk the snapshot of processes, and
	//display information about each process in turn
	do
	{
		

		WriteProcessName(pe32, hFile);
		WriteProcessID(pe32, hFile);
		WriteProcessSessionName(pe32, hFile);
		WriteProcessSessionId(pe32, hFile);
		WriteProcessMemUsage(pe32, hFile);
		WriteAndIncrementFile(hFile, lpcwstrLineDivider, dwLenLineDivider);

		/*
		_tprintf(TEXT("\n\n====================================================="));
		_tprintf(TEXT("\nProcess Name: %s"), pe32.szExeFile);
		_tprintf(TEXT("\n-------------------------------------------------------"));

		//Retrieve the priority class.
		dwPriorityClass = 0;
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		if (hProcess == NULL)
		{
			printError((TCHAR *) TEXT("OpenProcess"));
		}
		else
		{
			dwPriorityClass = GetPriorityClass(hProcess);
			if (!dwPriorityClass) printError((TCHAR *) TEXT("GetPriorityClass"));
			CloseHandle(hProcess);
		}

		_tprintf(TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID);
		_tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
		_tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
		_tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
		if (dwPriorityClass)
			_tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);

		ListProcessModules(pe32.th32ProcessID);
		ListProcessThreads(pe32.th32ProcessID);
		*/
		

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	int closed = CloseHandle(hFile);
	if (!closed) {
		printError((TCHAR*)TEXT("Can't close file."));
	}


	return TRUE;
}


BOOL WriteAndIncrementFile(HANDLE hFile, const TCHAR* DataBuffer, DWORD dwBytesToWrite) {

	if (INVALID_HANDLE_VALUE == hFile || NULL == DataBuffer) {
		//printError((TCHAR*)TEXT("Invalid parameters passed to WriteAndIncrementFile.")); 
		return FALSE; // I don't care here, I'll let the caller decide if FALSE is really bad here. 
	}

	BOOL bErrorFlag = WriteFileEx(
		hFile,							// Handle to open file 
		DataBuffer,						// pointer to start of data to write
		dwBytesToWrite,					// number of bytes to write
		&OverlappedIO,					// LP Overlapped
		LpoverlappedCompletionRoutine);	// Unused here

	OverlappedIO.Offset += dwBytesToWrite;	// And increment offset, so we can append more data

	if (FALSE == bErrorFlag)
	{
		printError((TCHAR*)TEXT("WriteFile error!"));
	}

	return bErrorFlag;
}

BOOL WriteProcessName(PROCESSENTRY32 pe32, HANDLE hFile) {
	DWORD dwBytesToWrite;
	DWORD dwBytesWritten;

	const TCHAR* DataBuffer = TEXT("\nProcess Name: ");
	dwBytesToWrite = wcsnlen_s(DataBuffer, maxCount) * sizeof(WCHAR); 
	BOOL bErrorFlag = WriteAndIncrementFile( hFile, DataBuffer, dwBytesToWrite );

	size_t procNameLen = wcsnlen_s(pe32.szExeFile, maxCount) * sizeof(WCHAR);
	bErrorFlag = WriteAndIncrementFile( hFile, pe32.szExeFile, procNameLen );

	return bErrorFlag;  // This only takes the second function calls return into consideration...
}

BOOL WriteProcessID(PROCESSENTRY32 pe32, HANDLE hFile) {
	DWORD dwBytesToWrite;
	DWORD dwBytesWritten;

	const TCHAR* DataBuffer = TEXT("\nProcess Id: ");
	dwBytesToWrite = wcsnlen_s(DataBuffer, maxCount) * sizeof(WCHAR);
	BOOL bErrorFlag = WriteAndIncrementFile(hFile, DataBuffer, dwBytesToWrite);

	TCHAR lpwstrPID [maxCount];
	DWORD dwPIDSize = -1;

	errno_t errNo = _itow_s((int)pe32.th32ProcessID, (wchar_t*)lpwstrPID, maxCount, 10);
	if (errNo != 0) {
		printError((TCHAR*)TEXT("Errno not zero after saving session ID to buffer."));
	}
	dwPIDSize = wcsnlen_s(lpwstrPID, maxCount) * sizeof(TCHAR);

	size_t procNameLen = wcsnlen_s(lpwstrPID, maxCount) * sizeof(WCHAR);
	bErrorFlag = WriteAndIncrementFile(hFile, lpwstrPID, procNameLen);

	return bErrorFlag;  // This only takes the second function calls return into consideration...
}

BOOL WriteLabel(const TCHAR* lpcwstrLabel, HANDLE hFile) {
	DWORD dwLabelSize = wcsnlen_s(lpcwstrLabel, maxCount) * sizeof(TCHAR);
	BOOL bErrorFlag = WriteAndIncrementFile(hFile, lpcwstrLabel, dwLabelSize);

	return TRUE;
}

BOOL WriteProcessMemUsage(PROCESSENTRY32 pe32, HANDLE hFile) {
	// From https://learn.microsoft.com/en-us/windows/win32/psapi/collecting-memory-usage-information-for-a-process
	HANDLE hProcess;
	PROCESS_MEMORY_COUNTERS pmc;

	// Print the process identifier.
	//printf("\nProcess ID: %u\n", pe32.th32ProcessID);

	// Print information about the memory usage of the process.

	hProcess = OpenProcess(
		PROCESS_QUERY_LIMITED_INFORMATION, // | PROCESS_VM_READ,
		FALSE, 
		pe32.th32ProcessID
	);
	if (NULL == hProcess) {
	
		failcount++;
		return FALSE;
	}

	if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
	{
		WriteLabel(TEXT("\nMem Usage: "), hFile);
		goodcount++;


		//pmc.WorkingSetSize
		if (180 == pe32.th32ProcessID) {
			printf("Mem usage for proc id 180:\n");
			printf("\tPageFaultCount: %d K\n", pmc.PageFaultCount/1000);
			printf("\tPeakWorkingSetSize: %d K\n", pmc.PeakWorkingSetSize /1000);
			printf("\tWorkingSetSize: %d K\n", pmc.WorkingSetSize / 1000);
			printf("\tQuotaPeakPagedPoolUsage: %d K\n", pmc.QuotaPeakPagedPoolUsage / 1000);
			printf("\tQuotaPagedPoolUsage: %d K\n", pmc.QuotaPagedPoolUsage / 1000);
			printf("\tQuotaPeakNonPagedPoolUsage: %d K\n", pmc.QuotaPeakNonPagedPoolUsage / 1000);
			printf("\tQuotaNonPagedPoolUsage: %d K\n", pmc.QuotaNonPagedPoolUsage / 1000);
			printf("\tPagefileUsage: %d K\n", pmc.PagefileUsage / 1000);
			printf("\tPeakPagefileUsage: %d K\n", pmc.PeakPagefileUsage / 1000);
		}
	}
	else {
		printError((TCHAR*)TEXT("Error getting process mem usage."));
		
	}

	DWORD dwWorkingSetKs = pmc.WorkingSetSize / 1000;
	DWORD dwWorkingSetKsSize = 0;
	TCHAR lpwstrSessionID[maxCount] = { 0 };
	errno_t errNo = _itow_s((int)dwWorkingSetKs, (wchar_t*)lpwstrSessionID, maxCount, 10);
	if (errNo != 0) {
		printError((TCHAR*)TEXT("Errno not zero after saving session ID to buffer."));
	}

	const TCHAR * lpwstrUnit = TEXT(" K");
	dwWorkingSetKsSize = wcsnlen_s(lpwstrSessionID, maxCount) * sizeof(TCHAR);
	size_t numElementsSessionID = wcsnlen_s(lpwstrSessionID, maxCount);
	size_t numElementsUnits = +wcsnlen_s(lpwstrUnit, maxCount);
	size_t numElements = numElementsSessionID + numElementsUnits;
	errNo = wcscat_s(
		(wchar_t*) lpwstrSessionID,
		maxCount,
		(wchar_t*) lpwstrUnit
	);  // Apparently, I have to manually null-terminate the string after concatonating!?
	if (errNo != 0) {
		printError((TCHAR*)TEXT("Errno not zero after adding units to buffer."));
	}

	dwWorkingSetKsSize = wcsnlen_s(lpwstrSessionID, maxCount) * sizeof(TCHAR);

	BOOL bErrorFlag = WriteAndIncrementFile(hFile, lpwstrSessionID, dwWorkingSetKsSize);
	

	CloseHandle(hProcess);

	return TRUE;
}

BOOL WriteProcessSessionId(PROCESSENTRY32 pe32, HANDLE hFile) {
	const TCHAR* lpwstrLabel = TEXT("\nSession #: ");
	DWORD dwLabelSize = wcsnlen_s(lpwstrLabel, maxCount) * sizeof(TCHAR);
	BOOL bErrorFlag = WriteAndIncrementFile(hFile, lpwstrLabel, dwLabelSize);
	
	DWORD dwSessionId;
	const DWORD dwUnknownId = -1;
	bErrorFlag = ProcessIdToSessionId(pe32.th32ProcessID, &dwSessionId);
	if (FALSE == bErrorFlag)
	{
		//printError((TCHAR*)TEXT("ProcessIdToSessionId error.")); // Maybe use something like this if being verbose.
		//return FALSE;
		dwSessionId = dwUnknownId; // It looks like I can't get the ID for session 0, so I'll just assume that's what I have here??
	}
	// errno_t _itow_s( int value, wchar_t *buffer, size_t size, int radix );
	TCHAR* lpwstrSessionID = NULL;
	DWORD dwSessionIDSize = 0;
	if (dwUnknownId == dwSessionId) {
		lpwstrSessionID = (TCHAR *) TEXT("Unknown");
		dwSessionIDSize = wcsnlen_s(lpwstrSessionID, maxCount) * sizeof(TCHAR);
		bErrorFlag = WriteAndIncrementFile(hFile, lpwstrSessionID, dwSessionIDSize);
	}
	else {
		TCHAR lpwstrSessionID[maxCount];
		errno_t errNo = _itow_s((int)dwSessionId, (wchar_t*)lpwstrSessionID, maxCount, 10);
		if (errNo != 0) {
			printError((TCHAR*)TEXT("Errno not zero after saving session ID to buffer."));
		}
		dwSessionIDSize = wcsnlen_s(lpwstrSessionID, maxCount) * sizeof(TCHAR);
		//printf("lpwstrSessionId: %s", lpwstrSessionID);
		bErrorFlag = WriteAndIncrementFile(hFile, lpwstrSessionID, dwSessionIDSize);
	}
	
	

	return bErrorFlag; // At least if we're ALL good to here, we'll return TRUE... 
}

BOOL WriteProcessSessionName(PROCESSENTRY32 pe32, HANDLE hFile) {
	// https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw
	//BOOL WTSQuerySessionInformationW(
	//	[in] HANDLE         hServer,
	//	[in]  DWORD          SessionId,
	//	[in]  WTS_INFO_CLASS WTSInfoClass,
	//	[out] LPWSTR  *        ppBuffer,
	//	[out] DWORD* pBytesReturned
	//	);

	DWORD dwSessionId = 0;
	DWORD bytesReturned = 0;
	WTS_INFO_CLASS wtsInfo = WTSWinStationName;
	TCHAR* lpwstrOutBuffer;
	const DWORD dwUnknownId = -1;
	BOOL bErrorFlag = ProcessIdToSessionId(pe32.th32ProcessID, &dwSessionId);
	if (FALSE == bErrorFlag)
	{
		//printError((TCHAR*)TEXT("ProcessIdToSessionId error.")); // Maybe use something like this if being verbose.
		//return FALSE;
		dwSessionId = dwUnknownId; // It looks like I can't get the ID for session 0, so I'll just assume that's what I have here??
	}

	BOOL result = WTSQuerySessionInformationW(
		WTS_CURRENT_SERVER_HANDLE,
		dwSessionId,
		wtsInfo,
		(LPWSTR*) &lpwstrOutBuffer,
		&bytesReturned
	);

	// I just used this for a quick test.
	//if (TRUE == result) {
		//wprintf_s(L"\noutBuffer: %s", lpwstrOutBuffer);
	//} 
	if (FALSE == result){
		printError((TCHAR*)TEXT("Error getting session name."));
	}

	const TCHAR* lpwstrLabel = TEXT("\nSession Name: ");
	DWORD dwLabelSize = wcsnlen_s(lpwstrLabel, maxCount) * sizeof(TCHAR);
	bErrorFlag = WriteAndIncrementFile(hFile, lpwstrLabel, dwLabelSize);
	if (FALSE == bErrorFlag) {
		printError((TCHAR*)TEXT("Error writing label for session name."));
		return FALSE;
	}

	DWORD dwSessionNameSize = wcsnlen_s(lpwstrOutBuffer, maxCount) * sizeof(TCHAR);
	bErrorFlag = WriteAndIncrementFile(hFile, lpwstrOutBuffer, dwSessionNameSize);
	if (FALSE == bErrorFlag) {
		printError((TCHAR*)TEXT("Error writing session name."));
		return FALSE;
	}

	// MSDN says to use this to free the out buffer:
	WTSFreeMemory(
		(PVOID) lpwstrOutBuffer
	);


	return TRUE;
}

BOOL ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	//Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printError((TCHAR *) TEXT("CreateToolhelp32Snapshot (of modules)"));
		return FALSE;
	}

	//Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	//Retrieve information about the first module,
	//and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		printError((TCHAR *) TEXT("Module32First"));
		CloseHandle(hModuleSnap);
		return FALSE;
	}

	//Now walk the module list of the process,
	//and display information about each module
	do
	{
		_tprintf( TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf( TEXT("\n     Executable     = %s"), me32.szExePath);
		_tprintf( TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf( TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
		_tprintf( TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
		_tprintf( TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		_tprintf( TEXT("\n     Base size      = %d"), me32.modBaseSize);
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return TRUE;
}

BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	//Take a snapshot of all running threads
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) return FALSE;

	//Fill in the size of the structure before using it.
	te32.dwSize = sizeof(THREADENTRY32);

	//Retrieve information about the first thread,
	//and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		printError((TCHAR *) TEXT("Thread32First"));
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	//Now walk the thread list of the system,
	//and display information about each thread
	//associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			_tprintf((TCHAR *) TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			_tprintf((TCHAR *) TEXT("\n     Base priority  = %d"), te32.tpBasePri);
			_tprintf((TCHAR *) TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);
			_tprintf((TCHAR *) TEXT("\n"));
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) && ((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

// Base from: https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
/*
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS and compile with -DPSAPI_VERSION=1

void PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get the process name.
    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    // Print the process name and identifier.

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    // Release the handle to the process.
    if (hProcess != 0) {
        CloseHandle(hProcess);
    }
}

int main(void)
{
    // Get the list of process identifiers.
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }


    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            PrintProcessNameAndID(aProcesses[i]);
        }
    }

    //Quick hack to see result:
    printf("Press any key when finished.");
    getchar();

    return 0;
}
*/

