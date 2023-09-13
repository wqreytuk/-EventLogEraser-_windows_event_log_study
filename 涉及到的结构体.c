#define DWORD64 uint64
#define DWORD uint

typedef struct _loc_18002027E_r14 {
    ...
    DWORD64 _20;                    // 0x3728ec，暂时不知道这个值是否是固定的，也不知道是啥含义 
                                    // 这个地方就是个未初始化的内存，后面readfile的时候会用到这个作为buffer   
                                    // ElfHeader
    ...
    DWORD64 _A0;                    // 日志文件的大小的地址 lpfilesize
    ...
    DWORD64 _D8;                    // 日志文件的句柄
    ...
}

typedef struct _loc_1800028E0_rcx {
    DWORD64 _0;                     // FileView类的vftable
    DWORD64 _8;                     // &(_loc_18002027E_r14->_20)
    DWORD64 _10;                    // &(_loc_18002027E_r14->_20)
    DWORD64 _18;                    // 日志文件的大小的地址lpfilesize，我不知道这个是啥时候存进来的
                                    // 这个会在 sub_1800029DC 中存进去，是通过计算
                                    // _28+_10来完成的
                                    // 也就是说 dq /c 1 (_loc_1800028E0_rcx->_28 + _loc_1800028E0_rcx->_10)
                                    // 就可以看到日志文件的大小 ? poi(poi(0000007bddb7e538+28)+poi(0000007bddb7e538+10))
    DWORD64 _20;                    // 0xffffffffffffffff，这个值会被 180002A9D 更新成0
    DWORD   _28;                    // 0x80
    BYTE    _2C;                    // 0
    ...
    WORD    _46;                    // 3，暂时不知道是啥意思
    ...
    BYTE    _98;                    // 0，不知道啥意思
    ...
    DWORD   _EC;                    // 1，不知道啥意思
}

typedef struct FileHeader {
    DWORD64 _0;                     // 00656c6946666c45，即：ElfFile\0
    ...
    DWORD   _20;                    // 0x80，FileHeader的大小，固定的
    ...
    DWORD   _7C;                    // crc校验和
}
