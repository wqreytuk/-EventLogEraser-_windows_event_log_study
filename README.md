上一个研究项目已经完成，再开个坑，研究windows的日志删除


需要从eventvwr开始下手

我猜测windows会在关机的时候把日志存储到

```
C:\Windows\System32\winevt\Logs
```

开机的时候再读回去

因此在windows运行期间，事件应该都是保存在内存中的
