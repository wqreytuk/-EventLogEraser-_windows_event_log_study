00000287`417f1b5f 4c894c2420      mov     qword ptr [rsp+20h],r9
00000287`417f1b64 4c89442418      mov     qword ptr [rsp+18h],r8
00000287`417f1b69 4889542410      mov     qword ptr [rsp+10h],rdx
00000287`417f1b6e 48894c2408      mov     qword ptr [rsp+8],rcx
00000287`417f1b73 4883ec18        sub     rsp,18h
00000287`417f1b77 488b442448      mov     rax,qword ptr [rsp+48h]
; 检测第六个参数的魔术字符串
00000287`417f1b7c 813800002a2a    cmp     dword ptr [rax],2A2A0000h
; 如果相等，进行下一步的处理
00000287`417f1b82 7407            je      00000287`417f1b8b  Branch

00000287`417f1b84 33c0            xor     eax,eax
00000287`417f1b86 e9a4000000      jmp     00000287`417f1c2f  Branch

; int flag=0
00000287`417f1b8b c744240400000000 mov     dword ptr [rsp+4],0
; int i=0
00000287`417f1b93 c7042400000000  mov     dword ptr [rsp],0
00000287`417f1b9a eb08            jmp     00000287`417f1ba4  Branch

00000287`417f1b9c 8b0424          mov     eax,dword ptr [rsp]
00000287`417f1b9f ffc0            inc     eax
00000287`417f1ba1 890424          mov     dword ptr [rsp],eax

; if i>=500 跳出循环
00000287`417f1ba4 813c24f4010000  cmp     dword ptr [rsp],1F4h
00000287`417f1bab 7d33            jge     00000287`417f1be0  Branch

; if (_handle_array[i] == 0)break;
00000287`417f1bad 48630424        movsxd  rax,dword ptr [rsp]
; 也就是说00000287`417f2000将会存储_handle_array数据的地址
; 那么我们在main函数中需要malloc两次，一次用于分配_handle_array数组的地址
; 另一个malloc是一个QWORD指针，用于存放_handle_array的地址，然后修正00000287`417f2000为我们的QWORD指针的地址
; QWORD指针-(00000287`417f1bb1+7)=偏移量  00000287`417f1bb1+7是RIP的值，这个偏移量占4个bytes，需要倒序写入，或者将其重新解释为dword指针，直接写入dword值
; 00000287`417f1bb1-00000287`417f1b5f是我们要的偏移量，相对于hookaddress的偏移
00000287`417f1bb1 488b0d48040000  mov     rcx,qword ptr [00000287`417f2000]
00000287`417f1bb8 833c8100        cmp     dword ptr [rcx+rax*4],0
00000287`417f1bbc 7502            jne     00000287`417f1bc0  Branch

00000287`417f1bbe eb20            jmp     00000287`417f1be0  Branch

00000287`417f1bc0 48630424        movsxd  rax,dword ptr [rsp]
00000287`417f1bc4 488b0d35040000  mov     rcx,qword ptr [00000287`417f2000]
00000287`417f1bcb 8b0481          mov     eax,dword ptr [rcx+rax*4]
00000287`417f1bce 39442420        cmp     dword ptr [rsp+20h],eax
00000287`417f1bd2 750a            jne     00000287`417f1bde  Branch

00000287`417f1bd4 c744240401000000 mov     dword ptr [rsp+4],1
00000287`417f1bdc eb02            jmp     00000287`417f1be0  Branch

00000287`417f1bde ebbc            jmp     00000287`417f1b9c  Branch

00000287`417f1be0 837c240400      cmp     dword ptr [rsp+4],0
00000287`417f1be5 7546            jne     00000287`417f1c2d  Branch

; 00000287`417f2010是counter
; 可以看到，我们需要记录挺多的偏移量
00000287`417f1be7 488b0522040000  mov     rax,qword ptr [00000287`417f2010]
00000287`417f1bee 486300          movsxd  rax,dword ptr [rax]
00000287`417f1bf1 488b0d08040000  mov     rcx,qword ptr [00000287`417f2000]
00000287`417f1bf8 8b542420        mov     edx,dword ptr [rsp+20h]
00000287`417f1bfc 891481          mov     dword ptr [rcx+rax*4],edx
00000287`417f1bff 488b050a040000  mov     rax,qword ptr [00000287`417f2010]
00000287`417f1c06 486300          movsxd  rax,dword ptr [rax]
; 00000287`417f2008是_region_addr
00000287`417f1c09 488b0df8030000  mov     rcx,qword ptr [00000287`417f2008]
00000287`417f1c10 488b542448      mov     rdx,qword ptr [rsp+48h]
00000287`417f1c15 488914c1        mov     qword ptr [rcx+rax*8],rdx
00000287`417f1c19 488b05f0030000  mov     rax,qword ptr [00000287`417f2010]
00000287`417f1c20 8b00            mov     eax,dword ptr [rax]
00000287`417f1c22 ffc0            inc     eax
00000287`417f1c24 488b0de5030000  mov     rcx,qword ptr [00000287`417f2010]
00000287`417f1c2b 8901            mov     dword ptr [rcx],eax

00000287`417f1c2d 33c0            xor     eax,eax

00000287`417f1c2f 4883c418        add     rsp,18h
00000287`417f1c33 c3              ret
