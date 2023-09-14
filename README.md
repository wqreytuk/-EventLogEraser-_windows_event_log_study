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
