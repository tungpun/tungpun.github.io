---
layout: post
title: "ABCTF - Encryption Service - Writeup"
date: 2016-07-19 16:27:14 +0700
comments: true
categories: 
---

Long time, no post.

Today, I am going to write about a Crypto challenge from [ABCTF](http://abctf.xyz/problems). Although it is just a competition for high school student, it still contains funny stuffs.

In this challange, they give us:

~~~
See if you can break this!! 
You can connect with nc 107.170.122.6 7765 and the source can be found [here](http://pastebin.com/UTkSDn4H).
~~~

Content of that file was extracted as below:

```python
#/usr/bin/env python
from Crypto.Cipher.AES import AESCipher

import SocketServer,threading,os,time
import signal

from secret2 import FLAG, KEY

PORT = 7765

def pad(s):
  l = len(s)
  needed = 16 - (l % 16)
  return s + (chr(needed) * needed)

def encrypt(s):
  return AESCipher(KEY).encrypt(pad('ENCRYPT:' + s.decode('hex') + FLAG))

class incoming(SocketServer.BaseRequestHandler):
    def handle(self):
        atfork()
        req = self.request

        def recvline():
            buf = ""
            while not buf.endswith("\n"):
                buf += req.recv(1)
            return buf
        signal.alarm(5)

        req.sendall("Send me some hex-encoded data to encrypt:\n")
        data = recvline()
        req.sendall("Here you go:")
        req.sendall(encrypt(data).encode('hex') + '\n')
        req.close()

class ReusableTCPServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
  pass

SocketServer.TCPServer.allow_reuse_address = True
server = ReusableTCPServer(("0.0.0.0", PORT), incoming)

print "Server listening on port %d" % PORT
server.serve_forever()
```

As you see, the service receives our message, uses [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) to encrypt the received message, then returns the ciphertext for us.

The key is fairly secret.

The blocksize is 16 bytes.

The cryto system uses ECB mode.

I verify that with some case studies:

```
➜  abctf python -c 'print "41" * 16' | nc 107.170.122.6 7765                                                                        
Send me some hex-encoded data to encrypt:
Here you go:cd7985389a47184ce3f957b15a1c45f3729e426405f3273470de17375b203fd4f4f4af26204581fa57313f57a1c57bae
➜  abctf python -c 'print "41" * 17' | nc 107.170.122.6 7765                                                                        
Send me some hex-encoded data to encrypt:
Here you go:cd7985389a47184ce3f957b15a1c45f356ef6d3f0e00fe8259a67b87a0cf8d4764851b9b4880d691d8e84fce0c35bbef
➜  abctf python -c 'print "41" * 32' | nc 107.170.122.6 7765                                                                        
Send me some hex-encoded data to encrypt:
Here you go:cd7985389a47184ce3f957b15a1c45f31c621e4e2c3a88d1aa65d60efa13b737729e426405f3273470de17375b203fd4f4f4af26204581fa57313f57a1c57bae
```

```
➜  abctf python -c 'print "41" * 16 + "42" * 16' | nc 107.170.122.6 7765                                                          
Send me some hex-encoded data to encrypt:
Here you go:cd7985389a47184ce3f957b15a1c45f3a8e1e0aeb6ec9e58900539dbf3b8b348e2c76f25146263bc14c8d4c2cdf87baef4f4af26204581fa57313f57a1c57bae
➜  abctf python -c 'print "43" * 16 + "42" * 16' | nc 107.170.122.6 7765                                                           
Send me some hex-encoded data to encrypt:
Here you go:c6245c02399859146b835ab639c2ec45d14401a93319c6f9705cdafe21743362e2c76f25146263bc14c8d4c2cdf87baef4f4af26204581fa57313f57a1c57bae
```

Now, I focus on the below information:

`PLAINTEXT = 'ENCRYPT:' + message + FLAG + padding`

Let draft:

``` 
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                             PLAINTEXT                                               |                                CIPHERTEXT                                                                                       |
|     prefix       |              message                           |  postfix        |                                                                                                                                 |
|                  | block 0 (16b) |  block 1 (16b) |     flag      |  padding        |              prefix                 |        block 0                    |             block 1              |   posfix           |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ENCRYPT:12345678    aaa ... aaA     aaa ... aaa     AEXAMPLE        0x0x0x0x ...    |   f53163fdcfc8923ed221f1acb77d79d9    ff714c1d533d7394f7d612cb0244c9a5    ff714c1d533d7394f7d612cb0244c9a5    . . .             |
| ENCRYPT:12345678    aaa ... aaa     aaa ... aaA     XAMPLEFLAG0x    0x0x0x0x ...    |   f53163fdcfc8923ed221f1acb77d79d9    ff714c1d533d7394f7d612cb0244c9a5    5bcd55b9108751d49c90e55156b693e2    . . .   <-        |
| - [ Let's try ] -                                                                                                                                                                                                     |
| ENCRYPT:12345678    aaa ... aaa     aaa ... aay     AEXAMPLEFLAG    0x0x0x0x ...    |   f53163fdcfc8923ed221f1acb77d79d9    ff714c1d533d7394f7d612cb0244c9a5    c6dfb6ca2e95061f3f489747a9863368    . . .             |
| ENCRYPT:12345678    aaa ... aaa     aaa ... aaz     AEXAMPLEFLAG    0x0x0x0x ...    |   f53163fdcfc8923ed221f1acb77d79d9    ff714c1d533d7394f7d612cb0244c9a5    fd69bf1e57642c703d9cdbea681e5f74    . . .             |
| ENCRYPT:12345678    aaa ... aaa     aaa ... aaA     AEXAMPLEFLAG    0x0x0x0x ...    |   f53163fdcfc8923ed221f1acb77d79d9    ff714c1d533d7394f7d612cb0244c9a5    5bcd55b9108751d49c90e55156b693e2    . . .   <- Found  |
| ENCRYPT:12345678    aaa ... aaa     aaa ... aaB     AEXAMPLEFLAG    0x0x0x0x ...    |   f53163fdcfc8923ed221f1acb77d79d9    ff714c1d533d7394f7d612cb0244c9a5    fe11d61bfa6a55edfcc8135b6923ec12    . . .             |
| ENCRYPT:12345678    . . .                                                           |                                                                                                                                 |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
```

Woah. I can guest the flag based on the crypto system.
The next stage is to write a script to automate the work.

```
from punpwn import *

def get_cip(data):
    pp = PunPwn('107.170.122.6', 7765)
    pp.recvuntil(':')
    pp.sent(data)
    pp.recvuntil('\n')
    resp = pp.recvuntil('\n')
    return resp.split(':')[1][:64]

def check(postfix):
    pad = (48 - len(postfix)) * '1'    
    cip1 = get_cip(pad)
    cip2 = get_cip(pad + postfix)    
    return cip1 == cip2

if __name__ == '__main__':        
    res = ''
    while True:        
        for i in range(48, 256):
            postfix = chr(i).encode('hex')
            print "res: ", res
            if check(res + postfix):
                res = res + postfix                
                break
```

My favor scripting lannguage is Python.
I use my own lib - (punpwn)[https://github.com/tungpun/punpwn], that was forked from (pwntools lib)[pwntools.readthedocs.org].