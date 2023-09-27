# 特点

本工具和其他日志清除工具的区别在于，我并不会直接删除掉指定的日志条目，由于windows的binxml编码标准提供了模板特性，所以直接删除掉日志条目
存在损坏整个日志文件的风险，因为被删除的日志条目很有可能定义了其他日志记录依赖的模板，并且同一chunk中的不同record之间还存在字符串的引用情况

而且直接删除日志条目，需要更新后续所有日志记录的recordid字段

本工具采用的方式是将目标record的eventdata部分的数据抹掉，具体的实现方式是将EventData模板的NormalSubstitutionToken替换成OptionalSubstitutionToken 

然后再将数据定义部分的长度字段设置为0，之后将实际数据部分全部清空，即可达到下面的效果

### 原始日志条目

![image](https://github.com/wqreytuk/-EventLogEraser-_windows_event_log_study/assets/48377190/bdf2476f-4100-45cc-b68f-8690910ef7c1)

![image](https://github.com/wqreytuk/-EventLogEraser-_windows_event_log_study/assets/48377190/9ccdee11-0957-43c2-a80b-113b8b45a68d)

### 修改后的日志条目

![image](https://github.com/wqreytuk/-EventLogEraser-_windows_event_log_study/assets/48377190/1340de84-1248-4262-a542-788600a3fd38)

![image](https://github.com/wqreytuk/-EventLogEraser-_windows_event_log_study/assets/48377190/570588df-c38c-4b30-82b8-a745e1506b7b)


可以看到在xml视图中EventData变成了空标签

另外就是你会发现EventID被修改了，一个record，从xml的角度来讲，根节点是Event，包含两个子节点
System和EventData，我们清空了EventData，但是System节点中也有一些数据是我们不想让别人看到的

我在程序中预设了EventID、Level、Task、Keywords四个字段，目标record的这四个字段会被修改成预设的值以最大限度地和正常的record混在一起

**理论上讲，本工具不会损坏日志文件，再修改完日志之后从eventvwr或者wevtutil对日志进行操作时不应该产生任何异常，如果有问题，欢迎提issue**


**本工具可以进一步修改为shellcode，然后注入到eventlog服务进程中，直接对日志进行修改，从而避免产生eventlog服务日志**

**shellcode部分不对外开放**



# 成品工具
https://github.com/wqreytuk/-EventLogEraser-_windows_event_log_study/releases/download/asd/ConsoleApplication2.exe

**(使用的时候将输出重定向到文件中可以极大的加快运行速度，因为打印很耗时间)**

可以直接暴力终止EventLog服务进程来解除日志文件的占用
![image](https://github.com/wqreytuk/-EventLogEraser-_windows_event_log_study/assets/48377190/0f2fd06a-9da9-427b-9546-413fe38169ac)

上一个研究项目已经完成，再开个坑，研究windows的日志删除


需要从eventvwr开始下手

我猜测windows会在关机的时候把日志存储到

```
C:\Windows\System32\winevt\Logs
```

开机的时候再读回去

因此在windows运行期间，事件应该都是保存在内存中的

我去，刚发现，这个目录里面的日志都是处于占用状态的

被eventlog服务的svchost进程占用

这个svchost进程会周期性的往evtx文件中写入，而且这些文件的句柄都是打开状态

我们需要注入该进程，同时进行内存和文件的删除或者内容替换


使用下面的代码，可以验证，eventlog服务进程的内存是可以被我们进行读取和写入的


https://github.com/wqreytuk/windows_event_log_study/blob/main/event_log_svchost_process_memory.c

这个进程可能不允许第三方的dll被加载进去

注入shellcode，hook住ntdll!NtWriteFile，直接返回，导致eventlog服务无法将日志写入evtx文件中，在重启之后，中间的所有日志都会丢失

shellcode:

https://github.com/wqreytuk/windows_event_log_study/blob/main/shellcode.c

主程序：

https://github.com/wqreytuk/windows_event_log_study/blob/main/%E4%B8%BB%E7%A8%8B%E5%BA%8F.c


# 内存中的日志

后面我们还需要删除掉暂存在内存中的日志




这个网站记录了windows事件结构体

https://www.sciencedirect.com/science/article/pii/S1742287607000424

备份链接：https://github.com/wqreytuk/windows_event_log_study/blob/main/eventlog.7z

上面那个网站不太行，用下面这个

https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc

备份链接

https://github.com/wqreytuk/windows_event_log_study/blob/main/event_log_format.asciidoc

不同种类的日志存放在内存中不同的区域当中，我需要找一下handle和内存区域之间的联系

# 存在的问题

现在有一个问题，就是无论传进来的是什么，我们的hook函数都是直接返回成功的，但是他好像有某种机制来检测实际上是否写入成功，可能是通过获取文件size来完成的

因此我们可能需要hook完整，也就是说只过滤掉真正的record，其他的我们通过调用正常的函数来正常写入

或者如果我们能够枚举eventlog进程中所有日志对象的实例，我们就能获取到handle的record区域地址的对应关系

又或者我们可以hook住rpc相关的函数，因为eventvwr肯定是从eventlog提供的rpc接口来拉取日志的，这样我们应该也能获取到record的地址

# ElfFile CRC计算程序

https://github.com/wqreytuk/windows_event_log_study/blob/main/ConsoleApplication2.cpp

# ELFchunk CRC计算程序

https://github.com/wqreytuk/windows_event_log_study/blob/main/elfchunk_crc.c

# 更新

之前都是误会，之所以我说更改一个bit就会导致文件错误是因为我修改的eventid是一个根本不存在的id，所以就报错了，但是如果你改成合法的eventid是没有问题的


# g更新

事实证明record是有crc的

binxml的格式可以在这里找到

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/7cdd0c95-2181-4794-a094-55c78b389358

# 计算elfchunk中record的crc

https://github.com/wqreytuk/windows_event_log_study/blob/main/%E8%AE%A1%E7%AE%97%E4%B8%80%E4%B8%AAchunk%E4%B8%ADrecord%E7%9A%84CRC.c


其中crc的结果在elfchunk头的0x34偏移 dword

计算的record是该elfchunk的所有record，结束位置是最后一个record指定的长度的位置，chunk的填充位不做计算


## elfchunk CRC的另一种计算方式

可以直接使用ntdll提供的rtlcomputecrc32来计算

https://github.com/wqreytuk/windows_event_log_study/blob/main/elf_chnk_new_way_crc.c

## 计算chunk中所有record的另一种计算方式

https://github.com/wqreytuk/windows_event_log_study/blob/main/record_crc_new_way.c


# 深入理解evtx record结构

重要参考文档：

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956

重要代码注释：
https://github.com/wqreytuk/windows_event_log_study/blob/main/Evt%E4%BB%A3%E7%A0%81%E6%B3%A8%E9%87%8A.7z

配套evtx文件

https://github.com/wqreytuk/windows_event_log_study/blob/main/asdasdasdasdad.evtx

注释的代码是python-evtx模块的库

https://github.com/williballenthin/python-evtx

代码，调试入口是evtx_record_structure.py


深入理解之实例分析：

https://github.com/wqreytuk/windows_event_log_study/blob/main/%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3record%E6%A0%BC%E5%BC%8F%EF%BC%8C%E7%A4%BA%E4%BE%8B%E5%88%86%E6%9E%90.md

解答了困扰我很长时间的疑惑


# 获取日志文件中所有的eventid

https://github.com/wqreytuk/windows_event_log_study/blob/main/get_all_record_event_id_from_evtx_file.c

# 下一步的工作

现在我们已经有能力获取到所有日志的eventid了，下一步我们要修改所有关键字段的值来隐藏掉我们不想让别人看见的信息

# 从文件中删除日志的工具

https://github.com/wqreytuk/windows_event_log_study/blob/main/%E6%97%A5%E5%BF%97%E5%88%A0%E9%99%A4%E7%A8%8B%E5%BA%8F.c
 


# shellcode for eventlog service

only for myself, you may hava to develop it on your own

https://github.com/wqreytuk/my_precious_shellcode/tree/main

