tagname部分

```
00 00 00 00 BA 0C 05 00 45 00 76 00 65 00 6E 00 74 00 00 00
```

` BA 0C`应该是后面那个unicode字符串的hash，但是前面4bytes的0我不知道是啥意思



OpenStartElementToken  0x41  morebit置位，说明后面还有attribute list



```
AttributeToken 
```

token是0x6,1bytes，紧跟着是4bytes的string offset，就是attribute name，这个offset的base是chunkheader起始地址

跟着attribute name的是token 0x5,ValueTextToken ,1bytes,然后是是type，0x1,StringType ，1bytes，然后是unicode，这个unicode和别的不同，它不以双0字节结尾，全靠开头的长度字段来限制结束位置，紧跟着字符串的是token 0x2,CloseStartElementToken 

紧跟着是token 0x1  OpenStartElementToken ，然后是2bytes的DependencyID，然后是size，4bytes，然后是string offset 4bytes



然后就是字符串然后02 close

然后0x41  open morebit置位，denpendid，size， string offset，然后就是string，但是跟上次不同，string后面跟了一个4byte的长度，**哦，我傻逼了，上一个也有，有没有这个4byte的字段，取决于more bit是否置位**

```
B6 00 00 00
```

而这个长度正好是attribute的全部长度

```
46 3D 03 00 00 00 00 00 00 4B 95 04 00 4E 00 61 00 6D 00 65 00 00 00 05 01 1A 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2D 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2D 00 45 00 76 00 65 00 6E 00 74 00 6C 00 6F 00 67 00 06 8C 03 00 00 00 00 00 00 29 15 04 00 47 00 75 00 69 00 64 00 00 00 05 01 26 00 7B 00 66 00 63 00 36 00 35 00 64 00 64 00 64 00 38 00 2D 00 64 00 36 00 65 00 66 00 2D 00 34 00 39 00 36 00 32 00 2D 00 38 00 33 00 64 00 35 00 2D 00 36 00 65 00 35 00 63 00 66 00 65 00 39 00 63 00 65 00 31 00 34 00 38 00 7D 00
```



上一个0x41token字符串后面并没有长度，但是现在这个有，估计是因为字符串后面跟的attribute list使用的也是more bit置位的token0x46

.,0x46表示我们有不止一个attribute，事实确实如此，我们有两个Attribute

```
Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"
```



46 token   string offset

```
46 3D 03 00 00
```

4bytes 0, 2bytes hash, 2bytes string len, unicode, 2bytes 0结尾

```
00 00 00 00 4B 95 04 00 4E 00 61 00 6D 00 65 00 00 00
```



然后是0x3  CloseEmptyElementToken ，说明provider是一个空element

```
<Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"></Provider>
```

然后是0x41 tokne，新的element出现，然后是dependid。这回不是0xffff，是0x03

```
41 03 00 4D 00 00 00 FA 03 00 00
```

那么我们应该怎么处理dependencyid嘞？答案是不管，python的库代码上面直接给这个字段写的是unknown，可见根本没有处理这个字段

跟着字符串后面的是

```
27 00 00 00 06 1B 04 00 00 8C 03 00 00 29 DA 0A 00 51 00 75 00 61 00 6C 00 69 00 66 00 69 00 65 00 72 00 73 00 00 00 0E 04 00 06
```

这个我一开始没有理解，费了点时间

0x27后面的attribute的所有长度

0x6token，attribute

0x41b,string偏移，

0x3c8，unknown，不管

然后是字符串hash，字符串长度，字符串

最后的4个字节，就是最后这4bytes我没有弄明白，最终看了标准，明白了

```
0E 04 00 06
```

```
  OptionalSubstitutionToken SubstitutionId ValueType
   SubstitutionId = WORD

```

0xe,token OptionalSubstitutionToken ，0x4，SubstitutionId, 0x6 value type  `UInt16Type = %x06`



然后是0x2 token， CloseStartElementToken ，然后是0xe OptionalSubstitutionToken   然后SubstitutionId，0x03 ,然后是类型 0x06,然后是0x4  EndElementToken 

```
<EventID Qualifiers="%0x0004">%0x0003</EventID>
```



```
01 0B 00 22 00 00 00 4E 04 00 00
```

01 token  0xB  dependencyid   0x22 长度，0x4e4 string offset

```
00 00 00 00 00 18 09 07 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00
```

4bytes unknown  2bytes hash,unicode string



```
02 0E 0B 00 04 04
```

02 token close tag, 0xe OptionalSubstitutionToken     id 0x0b, value type 0x4 UInt8Type ,end element 0x4

```
<Version>%0x000B</Version>
```



```
01 00 00 1E 00 00 00 77 04 00 00
```

new element   dependenid   size   offset 0x477



````
00 00 00 00 64 CE 05 00 4C 00 65 00 76 00 65 00 6C 00 00 00
````

```
0E 00 00 04 04
```





# 关于namehash的计算方法



```
BC 0F 05 00 78 00 6D 00 6C 00 6E 00 73 00 00 00
```

```c
#include<stdio.h>
#include <string.h>

void hash(const char* str)
{
    int hashVal = 0;
    int i = 0;
    for (i = 0; i < strlen(str); i++)
        hashVal = hashVal * 65599 + str[i];
    printf("%x", hashVal&0xffff);
}
int main() {
    hash("xmlns");
}
```









前面遗漏了一部分，在这里补上



首先是fragementheader

```
0F 01 01 00
```

然后是TemplateInstance

```
0C 01 CB 98 32 5B E6 0A 00 00 00 00 00 00 CB 98 32 5B E3 27 BB 55 DB 55 0E 10 7F 4A D7 9C F6 01 00 00
```

0xc 1bytes token

0x1  1bytes  unknown

CB 98 32 5B   someID  4bytes

E6 0A 00 00   some length

00 00 00 00  unknown

CB 98 32 5B E3 27 BB 55 DB 55 0E 10 7F 4A D7 9C   16bytes GUID

F6 01 00 00  some length    这个长度可以帮我们快速定位到datainstance部分，如果我们想要看eventid，那么这个字段可以帮助我们节省很多时间



然后是fragementheader

```
0F 01 01 00
```

然后是OpenStartElementToken 

```
41 11 00 EA 01 00 00 4D 02 00 00 73 00 00 00 06 6A 02 00 00
```

0x41 1bytes token   more bit 置位

11 00   dependenid  2bytes

EA 01 00 00 some length

4D 02 00 00  offset   **这个offset可能在不同的record是同一个，因为他们使用了同一个字符串**，**这也就是为什么我们不能简单粗暴的直接清空一个record的内容，因为你清空的这条record里面的string很有可能正在被别的record使用**

73 00 00 00   4bytes   unkonwn



```
06 6A 02 00 00
```

06  1bytes token   AttributeToken 

6A 02 00 00   offset



```
05 01 35 00 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 73 00 63 00 68 00 65 00 6D 00 61 00 73 00 2E 00 6D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2E 00 63 00 6F 00 6D 00 2F 00 77 00 69 00 6E 00 2F 00 32 00 30 00 30 00 34 00 2F 00 30 00 38 00 2F 00 65 00 76 00 65 00 6E 00 74 00 73 00 2F 00 65 00 76 00 65 00 6E 00 74 00
```

05 token    ValueTextToken 

01 type string

35 00 string length

后面的是unicode string



## 手把手教你如何定位eventid



目前看来，就没有不使用template的record，基本上都会使用template



我们以配套evtx文件的第一条记录为例



 首先略过0x18字节，到达



```
0F 01 01 00
```

略过0x4bytes，到达

```
0C 01 FD 9A 00 D8 26 02 00 00 00 00 00 00 FD 9A 00 D8 2E AB 12 51 6F 19 EE A6 C9 2A A7 82 4D 05 00 00
```

C token 01 unknown

FD 9A 00 D8  unkown

26 02 00 00  some size

00 00 00 00  unkown

FD 9A 00 D8 2E AB 12 51 6F 19 EE A6 C9 2A A7 82  16bytes GUID

0x54d templatedef长度  从这个字段往后+0x54d就可以到达templatedatadef部分

即0x123e+54d=0x178b



现在我们达到templatedatadef部分

```
14 00 00 00
```

读出来4bytes，是data的数量，一共是0x14个，每个占4bytes(长度2bytes，类型2bytes)，那么templatedatadef部分一共占用4+0x14*4=0x54









那么也就是说0x178b+0x54=0x17cf,就是templateinstancedata的实际部分



现在我们已经有了各个部分的地址了



下面我们需要通过templatedef部分找到eventid tag，binxml贴心的设计了namehash，这样我们就不用再比较字符串了，只要对比一下name hash是不是eventid的hash就行了，而eventid的namehash是`0x61f5`



好了，我们接着templatedef头往下看

```
0F 01 01 00
```

然后

```
41 FF FF 41 05 00 00 4D 02 00 00
```

41 token  more bit置位

ffff depenid  忽略

0x541 elementdata len

0x2d4 nameoffset（相对于elfchunk）

elfchunk地址0x1000

0x1000+0x24d=0x124d

```
00 00 00 00 BA 0C 05 00 45 00 76 00 65 00 6E 00 74 00 00 00
```

00 00 00 00 unkown

BA 0C namehash

05 00    unicdeostring len

45 00 76 00 65 00 6E 00 74 00 00 00  unicodestring

然后：

```
87 00 00 00
```

这4个字节只有在morebit置位的时候才会出现

然后：

```
06 6A 02 00 00 00 00 00 00 BC 0F 05 00 78 00 6D 00 6C 00 6E 00 73 00 00 00 05 01 35 00 68 00 74 00 74 00 70 00 3A 00 2F 00
```

6  AttributeToken 

6A 02 00 00  nameoffset

0x126a：

```
00 00 00 00 BC 0F 05 00 78 00 6D 00 6C 00 6E 00 73 00 00 00
```

结构和上面那个string是一样的

然后：

```
05 01 35 00 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 73 00 63 00 68 00 65 00 6D 00 61 00 73 00 2E 00 6D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00
```

5   ValueTextToken 

1 type string

```
35 00 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 73 00 63 00 68 00 65 00 6D 00 61 00 73 00 2E 00 6D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2E 00 63 00 6F 00 6D 00 2F 00 77 00 69 00 6E 00 2F 00 32 00 30 00 30 00 34 00 2F 00 30 00 38 00 2F 00 65 00 76 00 65 00 6E 00 74 00 73 00 2F 00 65 00 76 00 65 00 6E 00 74 00
```

注意value部分的unicode虽然也有长度描述，但是没有双0bytes封口

然后

```
02
```

CloseStartElementToken 闭合tag

```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
```



然后

```
01 FF FF 6A 04 00 00 F8 02 00 00 00 00 00 00 6F 54 06 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 02 41 FF FF D9 00 00 00 1A 03 00 00 00 00 00 00 F1 7B
```

1  OpenStartElementToken 

FF FF 忽略

6A 04 00 00 some size

F8 02 00 00 nameoffset

0x12f8：

```
00 00 00 00 6F 54 06 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00
```

unicodestring结构

```
02
```

闭合

```
<System>
```



然后：

```
41 FF FF D9 00 00 00 1A 03 00 00 00 00 00 00 F1 7B 08 00 50 00 72 00 6F 00 76 00 69 00 64 00 65 00 72 00 00 00 B6 00 00 00 46 3D 03 00 00 00 00 00
```

开tag，more bit置位

FF FF 忽略

D9 00 00 00  some size

1A 03 00 00  nameoffset

0x131a:

````
00 00 00 00 F1 7B 08 00 50 00 72 00 6F 00 76 00 69 00 64 00 65 00 72 00 00 00
````

由于morebit置位，会多出来下面这个字段(我们并不关心该字段的真正含义)

```
B6 00 00 00
```

然后：

```
46 3D 03 00 00 00 00 00 00 4B 95 04 00 4E 00 61 00 6D 00 65 00 00 00 05 01 1A 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2D 00 57 00 69 00 6E
```

46  AttributeToken  morebit置位

3D 03 00 00 nameoffset

0x133d：

```
00 00 00 00 4B 95 04 00 4E 00 61 00 6D 00 65 00 00 00
```

然后

```
05 01 1A 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2D 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2D 00 45 00 76 00 65 00 6E 00 74 00 6C 00 6F 00 67 00 06 8C 03 00 00 00 00 00 00
```

5  ValueTextToken 

1  type string

1a 00 长度

下面读取长度0x1a的unbicidestring(0x1a*2=0x34 bytes)

```
4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2D 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2D 00 45 00 76 00 65 00 6E 00 74 00 6C 00 6F 00 67 00
```



然后：因为前面的46，more bit置位，说明不止一个attribute，我们是可以预测到后面的token肯定还是AttributeToken  

```
06 8C 03 00 00 00 00 00 00 29 15 04 00 47 00 75 00 69 00 64 00 00 00 05 01 26 00 7B 00 66 00 63 00 36 00 35 00 64 00 64 00 64 00 38 00 2D 00 64 00 36 00 65 00 66 00 2D 00 34 00 39 00 36 00 32 00 2D 00 38 00 33 00 64 00
```

06 AttributeToken   没有morebit说明是最后一个attribute了

8C 03 00 00 nameoffset

0x138c:

```
00 00 00 00 29 15 04 00 47 00 75 00 69 00 64 00 00 00
```

value:

```
05 01 26 00 7B 00 66 00 63 00 36 00 35 00 64 00 64 00 64 00 38 00 2D 00 64 00 36 00 65 00 66 00 2D 00 34 00 39 00 36 00 32 00 2D 00 38 00 33 00 64 00 35 00 2D 00 36 00 65 00 35 00 63 00 66 00 65 00 39 00 63 00 65 00 31 00 34 00 38 00 7D 00
```

然后

```
03
```

CloseEmptyElementToken 

```
<Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"></Provider>
```

然后

```
41 03 00 4D 00 00 00 FA 03 00 00 00 00 00 00 F5 61 07 00 45 00 76 00 65 00 6E 00 74 00 49 00 44 00 00 00 27 00 00 00 06 1B 04 00 00 8C 03 00 00 29 DA 0A 00 51 00 75 00 61 00 6C 00 69 00 66 00 69 00 65 00 72 00 73 00 00 00 0E 04 00 06 02 0E 03 00 06 04 01 0B 00 22 00 00 00 4E 04 00 00 00 00 00 00 18 09 07 00 56 00 65 00 72 00 73 00 69 00
```

41 OpenStartElementToken  morebit置位

03 00 忽略

4D 00 00 00 忽略

FA 03 00 00 nameoffset

0x13fa:

```
00 00 00 00 F5 61 07 00 45 00 76 00 65 00 6E 00 74 00 49 00 44 00 00 00 27 00 00 00 06 1B 04 00 00 8C 03 00 00 29 DA 0A 00 51 00 75 00 61 00 6C 00 69 00 66 00 69
```

得到namehash F5 61，小端转大端，0x61f5，就是我们要的eventid，从当前的offset，+2（namehash）+2（unciodelen）+（7+1）*2

===》offset+0x14  ---》0x13fe+0x14==0x1412

由于more bit置位，会多出来下面这4bytes

```
27 00 00 00
```



然后：

```
06 1B 04 00 00 8C 03 00 00 29 DA 0A 00 51 00 75 00 61 00 6C 00 69 00 66 00 69 00 65 00 72 00 73 00 00 00 0E 04 00 06 02 0E 03 00 06 04 01 0B 00 22 00 00 00 4E 04 00 00
```

06 AttributeToken 

 1B 04 00 00  nameoffset



0x141b：

```
8C 03 00 00 29 DA 0A 00 51 00 75 00 61 00 6C 00 69 00 66 00 69 00 65 00 72 00 73 00 00 00	
```

string结构

然后

```
0E 04 00 06 02 0E 03 00 06 04 01 0B 00 22 00 00 00 4E 04 00 00 00
```

e   OptionalSubstitutionToken 

04 00  SubstitutionID

6 typeid  UInt16Type (2bytes)

02 CloseStartElementToken   闭合

```
<EventID Qualifiers="">
```

然后：

```
0E 03 00 06 04 01 0B 00 22 00 00 00 4E 04 00 00 00
```

可以得到SubstitutionID是0x3  也就是templateinstancedata部分的第4个（SubstitutionID是从0开始的）



但是我们必须要看templateinstancedatadef部分，因为有一些是OptionalSubstitutionToken ，也就是说如果def部分的长度和类型都是0（连续4bytes的0），如果这种情况出现在0x3之前，那么在templateinstancedata部分我们的排位就会上升，也就是说如果0x2是4bytes的0，那么我们在templateinstancedata对应的数据就是第0x2个



所以我们现在跳到templateinstancedatadef部分，0x178b

跳过4bytes的entry个数然后4bytes为单位进行浏览，每次取出来4bytes（dword），在遍历到第0x3之前，如果有0，就0x3--，当前实例是没有

另外就是在遍历的同时我们要记下来遍历的每一个dword的&0xffff的结果并进行累加（数据长度）--》datalen

所以我们现在跳到templateinstancedata部分，0x17cf,

跳过datalen字节，即4bytes，0x17e3，取出来一个word，eventid的值都是word类型，这个是固定的（UInt16Type = %x06）

取出来值是0x44e,就是eventid--》1102





# 注意



在binxxml中

eventdata和userdata的嵌入是有区别的



userdata的嵌入方式为

```
<EVENT>
...
<USERDATA>
%1
</USERDATA>
</EVENT>
```

eventdata的嵌入方式为

```
<EVENT>
...
%1
</EVENT>

<EVENTDATA>标签存在于实际数据部分
```

实例：

userdata

```
01 13 00 24 00 00 00 69 07 00 00 ED 05 00 00 35 44 08 00 55 00 73 00 65 00 72 00 44 00 61 00 74 00 61 00 00 00 02 0E 13 00 21 04 04 00
```



evetdata:

```
41 FF FF 12 00 00 00 1F 07 00 00 09 00 00 00 06 42 07 00 00 0E 0C 00 13 03 04 0E 11 00 21 04 00
```

这个翻译过来就是

```
<EVENT>
<System>
...
<Security UserID=""></Security>
</System>
%1
</EVENT>
```

