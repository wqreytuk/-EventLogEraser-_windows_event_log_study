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
