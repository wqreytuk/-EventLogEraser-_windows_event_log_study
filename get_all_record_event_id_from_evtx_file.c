#include<windows.h>
#include<stdio.h>

// 获取日志文件中所有记录的eventid并输出
int main() {
	// 打开文件，逐个chunk进行遍历
     HANDLE _file_handle = CreateFileA("C:\\Users\\123\\Documents\\7",
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if ((DWORD64)_file_handle == -1) {
        printf("[-] open evtx file failed, abort...\n");
        return -1;
    }
    // 日志文件中就算只有一条record，都会至少包含一个chunk，也就是说filesize-0x1000总是0x10000的倍数，不够的地方他会进行padding
    // 首先我们要获取文件的size，用于判断越界
    // 正常来讲都用不到DWORD64来表示文件大小，不过我们还是严谨一点
    DWORD _FileSizeHigh;
    DWORD _FileSizeLow = GetFileSize(_file_handle, &_FileSizeHigh);
    DWORD64 _file_size = ((DWORD64)_FileSizeHigh << 32) + _FileSizeLow;
    DWORD64 _current_chunk = 0;
    while (1) {
        // 重置文件指针
        SetFilePointer(_file_handle, 0x1000+ 0x10000 * _current_chunk, NULL, FILE_BEGIN);
        // 我们先把record的个数读出来，elfchunk有价值的部分只有0x80bytes
        BYTE* _elfchunk_buffer = (BYTE*)malloc(0x80);
        if (0 == _elfchunk_buffer) {
            printf("[-] odd! memory allocate failed, abort...\n");
            break;
        }
        ZeroMemory(_elfchunk_buffer, 0x80);
        DWORD _out = 0;
        if (!ReadFile(_file_handle,
            _elfchunk_buffer,
            0x80,
            &_out,
            NULL
        )) {
            printf("[-] read evtx file failed, abort...\n");
            return -1;
        }
        // 0x10偏移就是record的个数（最后一条record的序号，从1开始）
        DWORD64 _record_num = *(reinterpret_cast<DWORD64*>(_elfchunk_buffer + 0x10));
        printf("[*] total 0x%08p records in chunk: 0x%08p\n", reinterpret_cast<DWORD64*>(_record_num), reinterpret_cast<DWORD64*>(_current_chunk));
        free(_elfchunk_buffer);

        // 判断是否已经遍历完了所有的chunk
        if (0x1000 + 0x10000 * ++_current_chunk == _file_size)
            break;
    }
    CloseHandle(_file_handle);
}
