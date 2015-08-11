---
layout: post
title: "FCTF Easy PHP Writeup"
date: 2015-08-06 20:49:02 +0700
comments: true
categories: 
---
Last week, when fed my brain with CTF, i faced a web challenge. Luckily, with the help from my friend, i solved it.
This challenge may be easy, but with me, it is interesting and i studied something. So, tonight, i spend my gaming time to explain about this.

My English is terrible, however, i will try with my best.

This challenge give us the url to the web page which have written by php. For personal reason, i can't show it here.

Here we go,
after viewing source, i found the piece of backend code:

```
<?php

    function h($s){return htmlspecialchars($s,ENT_QUOTES,'UTF-8');}
    function crc32_string($v){return sprintf("%08x", crc32($v) & 0xffffffff);}

    $value = (isset($_POST['value']) && is_string($_POST['value'])) ? $_POST['value'] : '';

    $flag = ($value !== "" && $value !== "ecTmZcC" && crc32_string($value) == crc32_string('ecTmZcC')) ? 'CENSORED': 'bad value';
?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>For PHP Expert</title>
  </head>
  <body>
    <p>
       PHP is a magic language &lt;3. <br>Enter a good value and I'll give you flag ;)
    </p>
    <form method="POST">
      <div>Value: <input type="text" name="value" value="<?php echo h($value); ?>"></div>
      <br>
      <div><input type="submit" value="Submit"></div>
    </form>
    <br>
    <?php echo $flag ?>
  </body>
  <!-- magic.phps -->
</html>
```

As you see, to solve this challenge, we have to find a `value` , which is not `ecTmZcC` but its crc32 is equal to `ecTmZcC`'s crc32 :|

Seem like crazy, right ?

Or you can think more positive: is something wrong with  `==` in php (php is famous for that) ?
The key is [Magic Hash](https://blog.whitehatsec.com/magic-hashes/)

`ecTmZcC`'s crc32 is `0e730435`. So, we must calculate a value which has crc32 hash similar '0eXXXXXX' (X is numeric).

I wrote a Python script to find it.

```
!#/usr/bin/python2.7
import binascii

def CRC32(buf):    
    buf = (binascii.crc32(buf) & 0xFFFFFFFF)
    return "%08X" % buf


def chk(s, p):
	if s[:2] != p:
		return False
	for c in s[2:]:
		if '0' <= c <= '9':
			ok = 1
		else:
			return False
	return True


if __name__ == '__main__':
	pattern = CRC32('ecTmZcC')[:2]	# 0e
	i = 0
	while True:
		if chk(CRC32(str(i)), pattern):			
			print 'value:', i
			break	
		i += 1		
```

Finally, we have the answer: **6586** and got flag :D