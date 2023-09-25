#include<windows.h>
#include<stdio.h>
#include <tchar.h>
#include <strsafe.h>
// 禁用padding
#pragma pack(1)

// #define DEBUG

#define TARGET_EVENT_ID 4728

#define EVENT_NAME_HASH 0x0CBA
#define SYSTEM_NAME_HASH 0x546F
#define EVENTID_NAME_HASH 0x61F5
#define USERDATA_NAME_HASH 0x4435
#define EVENTDATA_NAME_HASH 0x2844
// EventData标签的嵌入方式有点特别，详见
// https://github.com/wqreytuk/windows_event_log_study/blob/main/%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3record%E6%A0%BC%E5%BC%8F%EF%BC%8C%E7%A4%BA%E4%BE%8B%E5%88%86%E6%9E%90.md#%E6%B3%A8%E6%84%8F
#define EVENTDATA_NAME_HASH 0x8244
// 我们感兴趣的tag [OutterTemplate]
#define TASK_NAME_HASH 0x7B45
#define LEVEL_NAME_HASH 0xCE64
#define COMPUTER_NAME_HASH 0x6E3B
// 我们感兴趣的tag [InnerTemplate]
// 只有一个，就是Data标签，因为InnerTemplate只有Data标签
#define DATA_NAME_HASH 0x6F8A

#define ROOT_END 0x0E04
#define CHILD_END 0x0404

#define ENTRY_NUMBER 1024

typedef struct _TemplateInstace {
    BYTE    _template_instance_token;
    BYTE    _unknown;
    DWORD   _template_id;
    DWORD   _template_def_offset;
}TemplateInstace, * PTemplateInstace;

typedef struct _TemplateDef {
    DWORD   _unknown;
    GUID    _guid;
    DWORD   _template_def_length;
}TemplateDef, * PTemplateDef;

typedef struct _StartElement {
    BYTE    _open_start_element_token;
    WORD    _dependency_id;
    DWORD   _element_length;
    DWORD   _name_offset;
}StartElement, * PStartElement;

typedef struct _TagName {
    DWORD   _unknown;
    WORD    _name_hash;
    WORD    _unicode_string_length;
    // 后面跟的是unicode string，但是我们并不关心，我们只需要有name hash就可以判断tag name到底是啥了
}TagName, * PTagName;

typedef struct _Attribute {
    BYTE    _attribute_token;
    DWORD   _name_offset;
}Attribute, * pAttribute;

// templatedef偏移表
DWORD _Template_OFS_TABLE[ENTRY_NUMBER];    // outter template
DWORD _INNER_Template_OFS_TABLE[ENTRY_NUMBER];  // inner template

// templatedef中的关键tag的SubstitutionID
DWORD64 _Substitution_ID_TABLE[ENTRY_NUMBER][5];
/*
EVENTID | EVENTDATA | COMPUTER | LEVEL | TASK
*/
// table index
WORD _table_index;
WORD _inner_table_index; // _INNER_Template_OFS_TABLE

DWORD64 return_step_by_type(BYTE* _base, BYTE _type) {
    if (_type == 0x1) {
        WORD _string_len = *reinterpret_cast<WORD*>(_base);
        return 2 * ((DWORD64)_string_len + 1);
    }
    else {
        printf("[UNEXPECTED VALUE TYPE] oops! something I didn't expected\n");
        exit(-1);
    }
    return 0;
}

DWORD64 iterate_attribute_list(BYTE* _base, DWORD64 _template_def_offset, DWORD64 _init_ofs) {
    _init_ofs += 4;
    // 可能存在attribute list，因此这里需要进行循环
    while (1) {
        Attribute _attribute = *reinterpret_cast<pAttribute>(_base + _init_ofs);
        _init_ofs += sizeof(Attribute);
        // 判断是否引用了别的record
        if (!(_template_def_offset + _init_ofs > _attribute._name_offset)) {
            TagName _tag_name = *reinterpret_cast<PTagName>(_base + _init_ofs);
            _init_ofs += sizeof(TagName);
            // 略过unicode string
            _init_ofs += ((DWORD64)_tag_name._unicode_string_length + 1) * 2;
        }
        // 读值
        BYTE _token = *reinterpret_cast<BYTE*>(_base + _init_ofs);
        // 不同的token，需要进行不同的处理，对于value部分的token，有三种情况
        // ValueTextToken、NormalSubstitutionToken、OptionalSubstitutionToken
        // 后两种都是占用4bytes，前者需要根据value type来确定长度
        if (_token != 0x5) { // 我们这里直接忽略0x45的情况，因为Event和System标签都没有这种情况
            _init_ofs += 0x4;
        }
        else {
            if (_token == 0x45) {
                printf("[UNEXPECTED VALUE TOKEN] oops! something I didn't expected\n");
                exit(-1);
            }
            _init_ofs += 0x1;
            BYTE _value_type = *reinterpret_cast<BYTE*>(_base + _init_ofs);
            _init_ofs += 0x1;
            _init_ofs += return_step_by_type(_base + _init_ofs, _value_type);
        }
        // 判断Attribute的more bit是否置位
        if (!(_attribute._attribute_token & 0x40)) {
            break;
        }
    }
    return _init_ofs;
}

DWORD64 deal_target_tag(HANDLE _file_handle,DWORD64 _current_chunk,
    DWORD64 _template_def_offset, DWORD64 _ofs_in_template, BOOL* _p_is_reference_offset,
    BYTE* _chunk_buffer, PStartElement _start_element, PTagName _tag_name) {
    BOOL _is_reference_offset = *_p_is_reference_offset;
    WORD _column_index = 0;
    BOOL _jump = FALSE;
    if (!(_tag_name->_name_hash ^ EVENTID_NAME_HASH)) {
        printf("\t\tEventID tag name located at: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _template_def_offset + _ofs_in_template));
        _column_index = 0;
    }
    else if (!(_tag_name->_name_hash ^ USERDATA_NAME_HASH)) {
        printf("\t\tUserData tag name located at: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _template_def_offset + _ofs_in_template));
        // userdata标签不是我们感兴趣的标签，这个标签只有在clearlog事件中才会出现（至少目前来讲是这样的）
        printf("\t\t[CHECK IF THIS EVENT IS A CLEAR LOG EVENT]\n");
        return 0;
    }
    else if (!(_tag_name->_name_hash ^ COMPUTER_NAME_HASH)) {
        printf("\t\tComputer tag name located at: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _template_def_offset + _ofs_in_template));
        // OutterTemplate中的Computer标签并没有使用替换，而是直接将值跟在了后面
        // 对于这种情况，我们不存储他的SubstitutionID（主要他也没有这个东西），转而存储值得结构体的地址
        // length 2bytes  unicode 无双0封口
        _column_index = 2;
    }
    else if (!(_tag_name->_name_hash ^ LEVEL_NAME_HASH)) {
        printf("\t\tLevel tag name located at: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _template_def_offset + _ofs_in_template));
        _column_index = 3;
    }
    else if (!(_tag_name->_name_hash ^ TASK_NAME_HASH)) {
        printf("\t\tTask tag name located at: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _template_def_offset + _ofs_in_template));
        _column_index = 4;
    }
    if (!_is_reference_offset) {
        _ofs_in_template += ((DWORD64)_tag_name->_unicode_string_length + 1) * 2;
    }
    else {
        *_p_is_reference_offset = !_is_reference_offset;
    }
    if (_start_element->_open_start_element_token & 0x40) {
        // 存在attribute
        _ofs_in_template = iterate_attribute_list(_chunk_buffer + _template_def_offset, _template_def_offset, _ofs_in_template);
    }
    // CloseStartElementToken
    _ofs_in_template += 0x1;
    // 判断是否为Computer标签
    if (2 == _column_index) {
        // token和value type
        _ofs_in_template += 0x2;
        // 直接记录下Computer标签值的准确地址
        _Substitution_ID_TABLE[_table_index][_column_index] = 0x1000 + 0x10000 * _current_chunk + _template_def_offset + _ofs_in_template;
        // len和unicode
        _ofs_in_template += ((DWORD64)*reinterpret_cast<WORD*>(_chunk_buffer + _template_def_offset + _ofs_in_template) + 1) * 2;
        // EndElementToken 
        _ofs_in_template += 0x1;
        return _ofs_in_template;
    }
    if (!(_tag_name->_name_hash ^ DATA_NAME_HASH)) {
        // 对于EventData标签，我们并不想获取关于他的任何数据，我们指向修改掉他的token
        // 只要不是0xE(OptionalSubstitutionToken )，就修改成0xE
        if (0xE != *reinterpret_cast<BYTE*>(_chunk_buffer + _template_def_offset + _ofs_in_template)) {
            // 写入文件
            // 重置文件指针
            SetFilePointer(_file_handle, 0x1000 + 0x10000 * (LONG)_current_chunk + _template_def_offset + _ofs_in_template, NULL, FILE_BEGIN);
            BYTE _token = 0xE;
            DWORD _out = 0;
            if (!WriteFile(_file_handle, &_token, 1, &_out, NULL)) {
                printf("[-] write evtx file failed, abort...\n");
                exit(-1);
            }
        }
        // token id type
        _ofs_in_template += 0x4;
        // EndElementToken 
        _ofs_in_template += 0x1;
        return _ofs_in_template;
    }
    // 现在我们应该会看到一个OptionalSubstitutionToken，然后是SubstitutionId，至于value type我直接忽略，因为我知道每个tag对应的类型
    _ofs_in_template += 0x1;
    WORD _substitution_id = 0;

    _substitution_id = *reinterpret_cast<WORD*>(_chunk_buffer + _template_def_offset + _ofs_in_template);
    // SubstitutionId
    _ofs_in_template += 0x2;
    // 把关键_substitution_id存入表中
    _Substitution_ID_TABLE[_table_index][_column_index] = _substitution_id;
    // value type
    _ofs_in_template += 0x1;
    // EndElementToken 
    _ofs_in_template += 0x1;
    return _ofs_in_template;
}

VOID iterateTag(HANDLE _file_handle,BYTE* _chunk_buffer, PTemplateInstace _template_instance,
    DWORD64 _ofs_in_template,WORD _expect_table_entry, DWORD64 _current_chunk,
    WORD _end_mark){
    while (!(_expect_table_entry ^ 0xFFFF)) {
#ifdef DEBUG
        printf("[DEBUG] offset in template: 0x%p\n", reinterpret_cast<BYTE*>(_ofs_in_template));
        if (0x207 == _ofs_in_template)
            int a = 1;
#endif
        BOOL _is_reference_offset = FALSE;
#ifdef DEBUG
        printf("[DEBUG] consecutive token: 0x%p\n", reinterpret_cast<BYTE*>(*reinterpret_cast<WORD*>(_chunk_buffer + _template_instance->_template_def_offset + _ofs_in_template)));
#endif 
        if (_end_mark == CHILD_END) {
            // 如果碰到连续的两个TOKEN，0x4和0x4，说明EvenData模板已经遍历完了，直接跳出即可
            if (_end_mark == *reinterpret_cast<WORD*>(_chunk_buffer + _template_instance->_template_def_offset + _ofs_in_template-1)) // 这里-1是对eventdata的特殊处理
                break;
        }
        if (_end_mark == *reinterpret_cast<WORD*>(_chunk_buffer + _template_instance->_template_def_offset + _ofs_in_template)) {
            // 如果碰到连续的两个TOKEN，0x4和0xE，说明我们已经遍历到EVENTDATA标签了
            // 记录下来SubstitutionID，然后跳出循环即可
            // 略过这两个连续的token
            _ofs_in_template += 0x2;
            _Substitution_ID_TABLE[_table_index][1] = *reinterpret_cast<WORD*>(_chunk_buffer + _template_instance->_template_def_offset + _ofs_in_template);
            // 这时候就可以结束遍历了，直接跳出即可
            break;
        }
        // 我们要先判断一下token，是否为0x4 EndElementToken，需要跳过1byte
        if (0x4 == *reinterpret_cast<BYTE*>(_chunk_buffer + _template_instance->_template_def_offset + _ofs_in_template)) {
            _ofs_in_template += 0x1;
        }
        StartElement _start_element = *reinterpret_cast<PStartElement>(_chunk_buffer + _template_instance->_template_def_offset + _ofs_in_template);
        _ofs_in_template += sizeof(StartElement);
        // 对于StartElement，我们主要关心_name_offset，通过_name_offset可以定位到标签的名称
        TagName _tag_name = *reinterpret_cast<PTagName>(_chunk_buffer + _start_element._name_offset);
        // 每次用到_name_offset的时候，我们都应该多加小心，因为他完全可以是引用的位于别的record记录中的位置
        // 所以我们需要进行判断，判断这个_name_offset是否位于_template_instance._template_def_offset+_ofs_in_template的前面
        // 如果是这样的话，_ofs_in_template就不需要往后偏移sizeof(TagName)，
        if (!(_template_instance->_template_def_offset + _ofs_in_template > _start_element._name_offset)) {
            _ofs_in_template += sizeof(TagName);
        }
        else {
            _is_reference_offset = TRUE;
        }

        // 如果不是eventid节点，那么就根据_element_length来略过该节点
        // 但是并不是所有的节点我们都可以直接略过
        // Event作为根节点，是不能直接跳过去的
        // 以及作为EventID的父节点的System节点，也不可以被略过
        if (!((_tag_name._name_hash ^ EVENT_NAME_HASH) * (_tag_name._name_hash ^ SYSTEM_NAME_HASH) * (_tag_name._name_hash ^ EVENTDATA_NAME_HASH))) {
            // 如果当前节点是这两个节点中的任意一个，我们都要遍历整个tag来跳到子节点，因为里面有一些变长数据
            if (!_is_reference_offset) {
                _ofs_in_template += ((DWORD64)_tag_name._unicode_string_length + 1) * 2;
            }
            // 如果StartElement的more bit置位，会多出来4bytes
            // 而且后面跟的应该是Attribute
            if (_start_element._open_start_element_token & 0x40) {
                _ofs_in_template = iterate_attribute_list(_chunk_buffer + _template_instance->_template_def_offset, _template_instance->_template_def_offset, _ofs_in_template);
            }
            // CloseStartElementToken
            _ofs_in_template += 0x1;
        }
        else if (!((_tag_name._name_hash ^ EVENTID_NAME_HASH) * (_tag_name._name_hash ^ USERDATA_NAME_HASH) * (_tag_name._name_hash ^ COMPUTER_NAME_HASH) * (_tag_name._name_hash ^ LEVEL_NAME_HASH) * (_tag_name._name_hash ^ TASK_NAME_HASH))) {
            _ofs_in_template = deal_target_tag(_file_handle, _current_chunk, _template_instance->_template_def_offset, _ofs_in_template, &_is_reference_offset, _chunk_buffer, &_start_element, &_tag_name);
            // 如果返回值为0，说明当前处理的节点为EventData，所有我们关心的tag已经处理完毕
            // 直接跳出循环即可
            if (!_ofs_in_template)
                break;
        }
        // 对于InnerTemplate，需要进行特殊处理
        else if (_end_mark == CHILD_END) {
            // 我们不能判断tagname的hash，因为tagname全部都是Data
            _ofs_in_template = deal_target_tag(_file_handle, _current_chunk, _template_instance->_template_def_offset, _ofs_in_template, &_is_reference_offset, _chunk_buffer, &_start_element, &_tag_name);
        }
        else {
            // 对于其他的普通节点，我们直接通过_element_length跳过
            // 但是需要注意的是，_element_length指的长度包括StartElement的最后一个字段_name_offset
            // 因此我们需要-4
            _ofs_in_template += _start_element._element_length - 4;
            if (!_is_reference_offset)
                _ofs_in_template -= sizeof(TagName);
        }
    }
}

BYTE* retrieve_value_address(BYTE* _chunk_buffer, DWORD64 _substitution_id, DWORD64 _iterate_start, DWORD64 _real_data_offset) {
    DWORD64 _counter = 0;
    DWORD64 _step_over = 0;
    // 遍历datadef
    while (1) {
        if (_counter == _substitution_id) {
            // 我们感兴趣的标签完全有可能是一个可选替换，且没有实际值
            if (0 == *reinterpret_cast<DWORD*>(_chunk_buffer + _iterate_start + (DWORD64)4 * _counter))
                return reinterpret_cast <BYTE*>(0);
            break;
        }
        DWORD _temp_value = *reinterpret_cast<DWORD*>(_chunk_buffer + _iterate_start + (DWORD64)4 * _counter++);
        _step_over += _temp_value & 0xFFFF;
    }

    // 返回该字段的真正地址
    return _chunk_buffer + _real_data_offset + _step_over;
}

// 获取日志文件中所有记录的eventid并输出
int main() {
    // 打开文件，逐个chunk进行遍历
    HANDLE _file_handle = CreateFileA("C:\\Users\\123\\Documents\\asdasdasdasdad1.evtx",
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

    // 从elfheader中读取出下一条record的序号，-1即可获得最后一条record的序号
    BYTE* _elffile_header_buffer = (BYTE*)malloc(0x20);
    if (0 == _elffile_header_buffer) {
        printf("[-] odd! memory allocate failed, abort...\n");
        exit(-1);
    }
    ZeroMemory(_elffile_header_buffer, 0x20);
    DWORD _out = 0;
    if (!ReadFile(_file_handle,
        _elffile_header_buffer,
        0x20,
        &_out,
        NULL
    )) {
        printf("[-] read evtx file failed, abort...\n");
        return -1;
    }
    DWORD64 _last_record_sequence_number = *reinterpret_cast<DWORD64*>(_elffile_header_buffer + 0x18) - 1;
    free(_elffile_header_buffer);

    // 日志文件中就算只有一条record，都会至少包含一个chunk，也就是说filesize-0x1000总是0x10000的倍数，不够的地方他会进行padding
    // 首先我们要获取文件的size，用于判断越界
    // 正常来讲都用不到DWORD64来表示文件大小，不过我们还是严谨一点
    DWORD _FileSizeHigh;
    DWORD _FileSizeLow = GetFileSize(_file_handle, &_FileSizeHigh);
    DWORD64 _file_size = ((DWORD64)_FileSizeHigh << 32) + _FileSizeLow;
    DWORD64 _current_chunk = 0;
    DWORD64 _record_sequence_number = 0;
    // 直接将整个chunk读入内存，一个chunk占65KB
    BYTE* _chunk_buffer = (BYTE*)malloc(0x10000);
    if (0 == _chunk_buffer) {
        printf("[-] odd! memory allocate failed, abort...\n");
        exit(-1);
    }
    while (1) {
#ifdef DEBUG
        if (_current_chunk == 0x18) {
            int a = 1;
        }
#endif
        printf("[*] chunk [0x%p]\n", reinterpret_cast<DWORD64*>(_current_chunk));

        // 下面开始遍历所有的record
        ZeroMemory(_chunk_buffer, 0x10000);
        SetFilePointer(_file_handle, 0x1000 + 0x10000 * (LONG)_current_chunk, NULL, FILE_BEGIN);
        _out = 0;
        if (!ReadFile(_file_handle,
            _chunk_buffer,
            0x10000,
            &_out,
            NULL
        )) {
            printf("[-] read evtx file failed, abort...\n");
            return -1;
        }
        // 0x8偏移是当前chunk中第一条record的序号，0x10偏移是当前chunk中最后一条record的序号，
        DWORD64 _record_num = *reinterpret_cast<DWORD64*>(_chunk_buffer + 0x10) - *reinterpret_cast<DWORD64*>(_chunk_buffer + 0x8) + 1;
        printf("\ttotal 0x%p records in chunk: 0x%p\n\n", reinterpret_cast<DWORD64*>(_record_num), reinterpret_cast<DWORD64*>(_current_chunk));
        DWORD64 _last_record_sequence_number_in_current_chunk = *reinterpret_cast<DWORD64*>(_chunk_buffer + 0x10);
        DWORD64 _record_offset_sum = 0x200;
        while (1) {
            _record_sequence_number = *reinterpret_cast<DWORD64*>(_chunk_buffer + _record_offset_sum + 0x8);
            printf("\trecord [0x%p]\n", reinterpret_cast<DWORD64*>(_record_sequence_number));
            // 我们需要把record的时间戳和length提取出来
#ifdef DEBUG
            printf("[DEBUG] _record_offset_sum: 0x%p\n", reinterpret_cast<BYTE*>(_record_offset_sum));
#endif
            DWORD _record_length = *reinterpret_cast<DWORD*>(_chunk_buffer + _record_offset_sum + 0x4);
#ifdef DEBUG
            printf("[DEBUG] _record_length: 0x%p\n", reinterpret_cast<BYTE*>((DWORD64)_record_length));
#endif
            FILETIME _record_time_stamp = *reinterpret_cast<FILETIME*>(_chunk_buffer + _record_offset_sum + 0x10);
            SYSTEMTIME stUTC, stLocal;
            FileTimeToSystemTime(&_record_time_stamp, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            TCHAR szBuf[MAX_PATH] = { 0 };
            if (S_OK != StringCchPrintf(szBuf, MAX_PATH,
                TEXT("%02d/%02d/%d  %02d:%02d:%02d"),
                stLocal.wMonth, stLocal.wDay, stLocal.wYear,
                stLocal.wHour, stLocal.wMinute, stLocal.wSecond)) {
                printf("[-] filetime convert failed, abort...\n");
                exit(-1);
            }
            _tprintf(TEXT("\t\ttime stamp: %s\n"), szBuf);

            // 下面我们就要开始解析binxml了
            DWORD64 _ofs_in_record = _record_offset_sum;
            // 0x18 record header
            _ofs_in_record += 0x18;
            // 0x4  fragment header
            _ofs_in_record += 0x4;
            // 我现在默认所有的binxml都使用template，遇到例外再说
            // 不过，先判断一下也无妨
            if (0xc != *reinterpret_cast<BYTE*>(_chunk_buffer + _ofs_in_record)) {
                printf("[NO OUTTER TEMPLATE] oops! something I didn't expected\n");
                exit(-1);
            }
            TemplateInstace _template_instance = *reinterpret_cast<PTemplateInstace>(_chunk_buffer + _ofs_in_record);
            _ofs_in_record += sizeof(TemplateInstace);

#ifdef DEBUG
            printf("[DEBUG] template definition offset: 0x%p\n", reinterpret_cast<BYTE*>((DWORD64)_template_instance._template_def_offset));
#endif
            // 现在需要考虑这样一种情况，就是record2的templatedef用的是record1，也就是说record2的_template_instance._template_def_offset小于当前offset
            // 那么我们就可以通过判断上述事实是否成立来判断当前record是否使用了位于前面record中的template，如果是这样的话，TemplateInstanceData会立即出现在_ofs_in_record
            // 我们需要维护一张表，把templatedef和偏移量关联起来，因为在实际的evtx文件中，存在大量的
            // templatedef引用的情况，也就是说我们没有必要每次都解析一遍templatedef，因为很有可能这个
            // templatedef我们已经解析过了
            WORD _expect_table_entry = 0xFFFF;
            DWORD64 _template_instance_data_offset = 0;
            if (_template_instance._template_def_offset < _ofs_in_record) {
                _template_instance_data_offset = _ofs_in_record;
                // 进入该分支，说明是引用templatedef，那么在我们的表中肯定就已经保存的有了
                // 我们可以直接返回关键的SubstitutionID
                for (int i = 0; i < ENTRY_NUMBER; i++) {
                    if (_Template_OFS_TABLE[i] == _template_instance._template_def_offset) {
                        _expect_table_entry = i;
                        break;
                    }
                }
            }
            else {
                TemplateDef _template_definition = *reinterpret_cast<PTemplateDef>(_chunk_buffer + _template_instance._template_def_offset);
                _template_instance_data_offset = _ofs_in_record + sizeof(TemplateDef) + _template_definition._template_def_length;
                // 进入该分支，说明还没有被处理过，将该templatedef的偏移量添加到表中
                _Template_OFS_TABLE[_table_index] = _template_instance._template_def_offset;
            }
#ifdef DEBUG
            printf("[DEBUG] template instance data location: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _template_instance_data_offset));
#endif
            // 有了_template_instance_data_offset之后
            // 我们就可以计算出来真正的数据的位置
            DWORD64 _real_data_offset = _template_instance_data_offset + 0x4 + (DWORD64)4 * (*reinterpret_cast<DWORD*>(_chunk_buffer + _template_instance_data_offset));
#ifdef DEBUG
            printf("[DEBUG] substitution data location: 0x%p\n", reinterpret_cast<BYTE*>(0x1000 + 0x10000 * _current_chunk + _real_data_offset));
#endif
            // 下面我们需要解析template_def来找到eventid
            DWORD64 _ofs_in_template = 0;
            _ofs_in_template += sizeof(TemplateDef);
            // 0x4  fragment header
            _ofs_in_template += 4;
            // 遍历所有的tag
            // 这个循环需要重构成函数，因为后面还会被用到
            iterateTag(_file_handle, _chunk_buffer, &_template_instance, _ofs_in_template, _expect_table_entry, _current_chunk, ROOT_END);


            // 现在我们已经集齐了所有必要的元素，可以获得EventID标签的值了
            DWORD64 _iterate_start = _template_instance_data_offset + 0x4;
            WORD _current_index = 0;
            if (_expect_table_entry == 0xFFFF) {
                _current_index = _table_index;
                _table_index++;
            }
            else
                _current_index = _expect_table_entry;

            // 获取EventID标签值的地址
            WORD _event_id = * reinterpret_cast<WORD*>(retrieve_value_address(_chunk_buffer, _Substitution_ID_TABLE[_current_index][0], _iterate_start, _real_data_offset));
            printf("\t\tevent id: 0x%p\n\n", reinterpret_cast<BYTE*>((DWORD64)_event_id));
            // 获取EventData的地址
            DWORD64 _event_data_addr = 0;
            if (_Substitution_ID_TABLE[_current_index][1]) {
                BYTE* _addr = retrieve_value_address(_chunk_buffer, _Substitution_ID_TABLE[_current_index][1], _iterate_start, _real_data_offset);
                printf("\t\tEventData template address: 0x%p\n\n", reinterpret_cast<BYTE*>(_addr - _chunk_buffer + 0x1000 + 0x10000 * _current_chunk));
                _event_data_addr = _addr - _chunk_buffer;
            }
            // Computer标签的准确地址
            printf("\t\tComputer tag value address: 0x%p\n\n", reinterpret_cast<BYTE*>(_Substitution_ID_TABLE[_current_index][2]));
            // 获取Level的地址
            printf("\t\tevent level: 0x%p\n\n", reinterpret_cast<BYTE*>((DWORD64) * reinterpret_cast<BYTE*>(retrieve_value_address(_chunk_buffer, _Substitution_ID_TABLE[_current_index][3], _iterate_start, _real_data_offset))));
            // 获取Task的地址
            printf("\t\tevent task: 0x%p\n\n", reinterpret_cast<BYTE*>((DWORD64) * reinterpret_cast<WORD*>(retrieve_value_address(_chunk_buffer, _Substitution_ID_TABLE[_current_index][4], _iterate_start, _real_data_offset))));

            // 解析InnerTemplate（如果存在我们感兴趣的innertamplate的话）
            // InstanceDataDef实际数据后面的部分是填充，可以直接忽略
            // 我们可以通过遍历InnerTemplate，将其所有的Substitution修改成OptionalSubStitution类型
            // 然后将InstanceDataDef部分的长度全部修改为0，再将实际数据按照原来的长度填充为0即可
            // 我们不能在OutterTemplate通过这种方法来删除EventData的原因是，可能会有别的record单纯
            // 的依赖这个EventData模板，直接删除的话，会干扰到目标之外的日志
            if (_Substitution_ID_TABLE[_current_index][1]) {
                // fragment header
                DWORD64 _ofs_in_event_data = 0;
                _ofs_in_event_data += 0x4;
                // 正常情况下都是模板token，不过判断一下也无妨
                if (0xc != *reinterpret_cast<BYTE*>(_chunk_buffer + _event_data_addr + _ofs_in_event_data)) {
                    printf("[NO INNER TEMPLATE] oops! something I didn't expected\n");
                    exit(-1);
                }
                TemplateInstace _inner_template_instance = *reinterpret_cast<PTemplateInstace>(_chunk_buffer + _event_data_addr + _ofs_in_event_data);
                _ofs_in_event_data += sizeof(TemplateInstace);
                _expect_table_entry = 0xFFFF;
                _template_instance_data_offset = 0;
                if (_inner_template_instance._template_def_offset < _event_data_addr + _ofs_in_event_data) {
                    _template_instance_data_offset = _event_data_addr + _ofs_in_event_data;
                    for (int i = 0; i < ENTRY_NUMBER; i++) {
                        if (_INNER_Template_OFS_TABLE[i] == _inner_template_instance._template_def_offset) {
                            _expect_table_entry = i;
                            break;
                        }
                    }
                }
                else {
                    TemplateDef _inner_template_definition = *reinterpret_cast<PTemplateDef>(_chunk_buffer + _inner_template_instance._template_def_offset);
                    _template_instance_data_offset = _event_data_addr + _ofs_in_event_data + sizeof(TemplateDef) + _inner_template_definition._template_def_length;
                    // 进入该分支，说明还没有被处理过，将该templatedef的偏移量添加到表中
                    _INNER_Template_OFS_TABLE[_inner_table_index] = _inner_template_instance._template_def_offset;
                    _inner_table_index++;
                }
                DWORD64 _real_inner_data_offset = _template_instance_data_offset + 0x4 + (DWORD64)4 * (*reinterpret_cast<DWORD*>(_chunk_buffer + _template_instance_data_offset));
                _ofs_in_template = 0;
                _ofs_in_template += sizeof(TemplateDef);
                // 0x4  fragment header
                _ofs_in_template += 4;
                // 遍历所有的tag，修改替换类型为可选替换
                iterateTag(_file_handle, _chunk_buffer, &_inner_template_instance, _ofs_in_template, _expect_table_entry, _current_chunk, CHILD_END);

                // 如果是目标EventID，则执行下面的操作
                if (_event_id == TARGET_EVENT_ID) {
                    // 现在我们需要处理data部分了
                    DWORD _data_counter = *reinterpret_cast<DWORD*>(_chunk_buffer + _template_instance_data_offset);
                    // 获取原始数据的长度
                    DWORD _ori_data_len = 0;
                    DWORD64 _counter = 0;
                    _iterate_start = _template_instance_data_offset + 0x4;
                    while (1) {
                        if (_counter == _data_counter)
                            break;
                        _ori_data_len += (*reinterpret_cast<DWORD*>(_chunk_buffer + _iterate_start + (DWORD64)4 * _counter++)) & 0xFF00;
                    }
                    // 我们先把def部分清空
                    SetFilePointer(_file_handle, 0x1000 + 0x10000 * _current_chunk + _template_instance_data_offset + 0x4, NULL, FILE_BEGIN);
                    BYTE* _padding = (BYTE*)malloc(_ori_data_len);
                    if (0 == _padding) {
                        printf("[-] odd! memory allocate failed, abort...\n");
                        exit(-1);
                    }
                    DWORD _out = 0;
                    ZeroMemory(_padding, _ori_data_len);
                    if (!WriteFile(_file_handle, _padding, _data_counter * 4, &_out, NULL)) {
                        printf("[-] write evtx file failed, abort...\n");
                        exit(-1);
                    }
                    free(_padding);
                    // 然后把data部分清空
                    SetFilePointer(_file_handle, 0x1000 + 0x10000 * _current_chunk + _template_instance_data_offset + 0x4 + 4 * (DWORD64)_data_counter, NULL, FILE_BEGIN);
                    _out = 0;
                    _padding = (BYTE*)malloc(_ori_data_len);
                    if (0 == _padding) {
                        printf("[-] odd! memory allocate failed, abort...\n");
                        exit(-1);
                    }
                    ZeroMemory(_padding, _ori_data_len);
                    if (!WriteFile(_file_handle, _padding, _ori_data_len, &_out, NULL)) {
                        printf("[-] write evtx file failed, abort...\n");
                        exit(-1);
                    }
                    free(_padding);
                }
            }

            if (_record_sequence_number == _last_record_sequence_number_in_current_chunk) {
                printf("[+] all records in current chunk have been checked out\n\n");
                break;
            }
            // 重置文件指针
            _record_offset_sum += _record_length;
        }
        // 当前chunk遍历完成后应该重置所有的表及index，因为不存在跨chunk的引用
        ZeroMemory(_Template_OFS_TABLE, sizeof(_Template_OFS_TABLE));
        ZeroMemory(_Substitution_ID_TABLE, sizeof(_Substitution_ID_TABLE));
        _table_index = 0;
        // 判断是否已经遍历完了所有的chunk
        if (_record_sequence_number == _last_record_sequence_number) {
            printf("[+] DONE!\n");
            break;
        }
        _current_chunk++;
    }
    free(_chunk_buffer);
    CloseHandle(_file_handle);
}
