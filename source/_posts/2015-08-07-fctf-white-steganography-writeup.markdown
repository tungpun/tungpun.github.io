---
layout: post
title: "FCTF White Steganography Writeup"
date: 2015-08-07 01:20:57 +0700
comments: true
categories: 
---
In FCTF, there is a stegno challenge. It's quite simple, but, i had lost so this challenge took me about 40 mins.
This is a reason for me to write about it today.

I have a "white" picture:

![White](http://i.imgur.com/2ukiJIf.png)

When face a stegano challenge, the first thought in my mind is check metadata.

I used to use `exiftool`.

```
➜  fctf  exiftool 2ukiJIf.png
ExifTool Version Number         : 9.46
File Name                       : 2ukiJIf.png
Directory                       : .
File Size                       : 1088 bytes
File Modification Date/Time     : 2015:08:06 22:13:30-04:00
File Access Date/Time           : 2015:08:06 22:16:43-04:00
File Inode Change Date/Time     : 2015:08:06 22:16:43-04:00
File Permissions                : rw-r--r--
File Type                       : PNG
MIME Type                       : image/png
Image Width                     : 300
Image Height                    : 150
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 3779
Pixels Per Unit Y               : 3779
Pixel Units                     : Meters
Image Size                      : 300x150
```

Nothing to do more with exiftool.

I try viewing the raw data as hex. Too complicated with a pure white image. Is something injected in that file ? or LSB implemented ?
To ensure that, these forensics tools like `binwalk`, `foremost` and `stegsolve` can be useful.

```
➜  fctf  binwalk 2ukiJIf.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 300 x 150, 8-bit/color RGB, non-interlaced
91            0x5B            Zlib compressed data, compressed
```

I check zlib compressed data, but it is not what we need.
Now is your time, `foremost` !

```
➜  fctf  foremost -i 2ukiJIf.png
Processing: 2ukiJIf.png
|*|
```

I also spend ~20mins with StegSolve to ensure that file is not pure white.

Anything i have ignored ?

> Never give up

I write a piece of code to highlight the pixel which is not pure white (255, 255, 255)

```
#!/usr/bin/python2.7

import cv2
import numpy as np

if __name__ == '__main__':
	img = cv2.imread('2ukiJIf.png', 0)	
	s = ''
	for x in range(150):
		for y in range(300): 	
			if img[x][y] != 255:							
				s += '+'
			else:
				s += ' '
		s += '\n'
	f = open("out.txt", "w")
	f.write(s)	
```

Luck me, after openning the out file, i get flag.

```
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                                            
                                                      ++                                                                       ++                                                                                                      ++                                                                   
                                                      ++                                                                       ++                                                                                                      ++                                                                   
                                                                              ++                                                                                         ++                                                            ++                                                                   
                                                                              ++                                                                                         ++                                                            ++                                                                   
                                                      ++   ++    ++   ++++   +++++           ++++     ++++     ++++            ++   ++++            ++ +++      ++++    +++++            ++++   ++ +++      ++++    ++    ++   +++++++ ++ +++                                                               
                                                      ++   ++    ++  ++   +   ++            ++   +   ++  ++   ++  ++           ++  ++   +           +++  ++    ++  ++    ++             ++  ++  +++  ++    ++  ++   ++    ++  ++   ++  +++  ++                                                              
                                                      ++   ++    ++  ++       ++            ++      ++   ++  ++   ++           ++  ++               ++    ++  ++    ++   ++            ++   ++  ++    ++  ++    ++  ++    ++  ++   ++  ++    ++                                                             
                                                      ++   ++    ++  +++      ++            +++     ++   ++  ++   ++           ++  +++              ++    ++  ++    ++   ++            ++   ++  ++    ++  ++    ++  ++    ++  ++   ++  ++    ++                                                             
                                                      ++   ++    ++   ++++    ++             ++++   +++++++  +++++++           ++   ++++            ++    ++  ++    ++   ++            +++++++  ++    ++  ++    ++  ++    ++  ++   ++  ++    ++                                                             
                                                      ++   ++    ++     +++   ++               +++  ++       ++                ++     +++           ++    ++  ++    ++   ++            ++       ++    ++  ++    ++  ++    ++   +++++   ++    ++                                                             
                                                      ++   ++    ++      ++   ++                ++  ++       ++                ++      ++           ++    ++  ++    ++   ++            ++       ++    ++  ++    ++  ++    ++  ++       ++    ++                                                             
                                                      ++    ++  +++  +   ++   ++            +   ++   ++   +   ++   +           ++  +   ++           ++    ++   ++  ++    ++             ++   +  ++    ++   ++  ++    ++  +++   ++++++  ++    ++                                                             
                                                      ++     +++ ++   ++++     +++           ++++     ++++     ++++            ++   ++++            ++    ++    ++++      +++            ++++   ++    ++    ++++      +++ ++  ++    ++ ++    ++                                                             
                                                      ++                                                                                                                                                                      ++    ++                                                                      
                                                      ++                                                                                                                                                                      ++    ++                                                                      
                                                    +++                           +++++++++                          +++++++++            +++++++++                          +++++++++                                         ++++++                                                                       
                                                                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                              


```                                                                                                                                                   

Quite simple, right ? :D                                                                                                                                           