# ps2lrz - Poke Size to LRZip File

Usage: ps2lrz [-s] [-f] [-i] filename  
       ps2lrz [-h | -?]  
  -s   size in bytes.  
  -f   force overwrite of file size. CAUTION!!  
  -i   show file info, evaluate Magic Header Bytes, and exit.  
	If no option, info for filename will be shown.  
  -h|? (or no argument) show this help message.

## NEW Now supports lrzip-next v0.8 and v0.9  and v0.10 files

Updated magic header is 6 bytes smaller for v0.8 and
4 bytes smaller for v0.9 and v0.10 files.

v0.9 lrzip-next files stores compression levels and any
optional comment.

v0.10 lrzip-next files also stores BZIP3 compression block size.

## What?
`ps2lrz` is a C program to allow a user to poke an uncompressed
file size into an **lrzip** version 0.6 or **lrzip-next**
version 0.6 and later file.

`ps2lrz` can also decode information stored in the Magic Header
Bytes and present it in an easy to read format.

## Why?
`lrzip` version 0.6 files will not store an expected file size
in **lrz** files when STDIN or STDOUT is used. `lrzip-next`
will store an expected file size when STDIN is used, but not STDOUT
in most cases.

While not having an expected file size won't impact lrzip/lrzip-next
functionality or effectiveness, it is very useful when using the `-i`
option because without an expected file size, lrzip/lrzip-next can't
measure net compression.

```
Rzip compression: 1386443973800.0% 13864439738 / 0
Back end compression: 31.0% 4300751017 / 13864439738
Overall compression: 430075101700.0% 4300751017 / 0
```

## Encrypted Files not included
Encrypted files cannot at present store an expected file size. Instead
it uses the same Magic Header Bytes for storing hash loops and salt.

## How
After file compression with `lrzip` or `lrzip-next` if STDIN or STDOUT
are used, a file size may be presented if using **verbose** options.
If you know the number of bytes that were fed to the compressor, you
can use `ps2lrz`.

First, check and see if your **lrz** file needs a file size.
```
$ ps2lrz -i filename.lrz
Showing file info only
filename.lrz is an lrzip version 0.7 file
filename.lrz is not encrypted
filename.lrz uncompressed file size is 0 bytes
Dumping magic header 24 bytes
Byte Offset      Description/Content
===========      ===================
Magic Bytes 0-3: 4C 52 5A 49 LRZI
Bytes 4-5:       LRZIP Major, Minor version: 00, 07
Bytes 6-13:      LRZIP Uncompressed Size bytes: 00 00 00 00 00 00 00 00 
Bytes 14 and 15: unused
Byte  16:        LRZIP Filter 1
Bytes 17-21:     LZMA Properties Bytes; 5D 00 00 40 00 lc=3, lp=0, pb=2, Dictionary Size=4194304
Byte  22:        MD5 Sum at EOF: yes
Byte  23:        File is encrypted: no
```
Or if you have an `lrzip-next` version **0.8.x** file, the output will resemble this.
```
$ ps2lrz -i lrzip-next.git.tar.lrz
Showing file info only
lrzip-next.git.tar.lrz is an lrzip version 0.8 file
lrzip-next.git.tar.lrz is not encrypted
lrzip-next.git.tar.lrz uncompressed file size is 0 bytes
Dumping magic header 18 bytes
Byte Offset      Description/Content
===========      ===================
Magic Bytes 0-3: 4C 52 5A 49 LRZI
Bytes 4-5:       LRZIP Major, Minor version: 00, 08
Bytes 6-13:      LRZIP Uncompressed Size bytes: 00 00 00 00 00 00 00 00 
Byte  14:        MD5 Sum at EOF: yes
Byte  15:        File is encrypted: no
Byte  16:        LRZIP Filter 0
Byte  17:        LZMA Dictionary Size Byte 1A lc=3, lp=0, pb=2, Dictionary Size=33554432
```
Or, if you have an `lrzip-next` version **0.9.x** or **0.10.x** file, the output will resemble this.
```
$ ./ps2lrz /tmp/words.txt.lrz
/tmp/words.txt.lrz is an lrzip version 0.10 file
/tmp/words.txt.lrz is not encrypted
/tmp/words.txt.lrz uncompressed file size is 1,191,359 bytes
Dumping magic header 20 bytes
Byte Offset      Description/Content
===========      ===================
Magic Bytes 0-3: 4C 52 5A 49 LRZI
Bytes 4-5:       LRZIP Major, Minor version: 00, 0a
Bytes 6-13:      LRZIP Uncompressed Size bytes: BF 2D 12 00 00 00 00 00 
Byte  14:        Hash Sum at EOF: SHA 256
Byte  15:        File is encrypted: NONE
Byte  16:        LRZIP Filter 0 - None
Byte  17:        BZIP3 Compression and Block Size Size Byte 0xF5 -- BZIP3 Block Size: 5, 201,326,592
Byte  18:        Rzip / Lrzip-next Compression Levels 1 / 9
Archive Comment: ps2lrz comment example
```

**filename.lrz uncompressed file size is 0 bytes** shows you could use a file size.
This indicates that the lrz  file was created with `tar -I` or a pipe to STDOUT.

Using `lrzip -t` `lrzip-next -t`, you can retrieve the uncompressed file size.

```
$ lrzip-next -tv filename.tar.lrz
...
MD5 being used for integrity testing.
Decompressing...

Average DeCompression Speed: 274.397MB/s
[OK] - 16688998400 bytes                                
Total time: 00:00:58.21
```

## Poke File Size
```
$ ps2lrz -s 16688998400 filename.tar.lrz
New file size is 16688998400. Magic file size set to: 00 e8 bd e2 03 00 00 00
```
will add the uncompressed, expected file size to **filename.tar.lrz**. Now
`lrzip/lrzip-next -i` will function as expected.

Before ps2lrz|After ps2lrz -s 16688998400
---|---
Rzip compression: 1386443973800.0% 13864439738 / 0   | Rzip compression: 83.1% 13864439738 / 16688998400
Back end compression: 31.0% 4300751017 / 13864439738 | Back end compression: 31.0% 4300751017 / 13864439738
Overall compression: 430075101700.0% 4300751017 / 0  | Overall compression: 25.8% 4300751017 / 16688998400

And `ps2lrz -i` will confirm
```
ps2lrz -i ilename.tar.lrz
Showing file info only
filename.tar.lrz is an lrzip version 0.7 file
filename.tar.lrz is not encrypted
filename.tar.lrz uncompressed file size is 16688998400 bytes
Dumping magic header 24 bytes
Byte Offset      Description/Content
===========      ===================
Magic Bytes 0-3: 4C 52 5A 49 LRZI
Bytes 4-5:       LRZIP Major, Minor version: 00, 07
Bytes 6-13:      LRZIP Uncompressed Size bytes: 00 E8 BD E2 03 00 00 00 
Bytes 14 and 15: unused
Byte  16:        LRZIP Filter 1
Bytes 17-21:     LZMA Properties Bytes; 5D 00 00 40 00 lc=3, lp=0, pb=2, Dictionary Size=4194304
Byte  22:        MD5 Sum at EOF: yes
Byte  23:        File is encrypted: no
```
Or if you have an `lrzip-next` version **0.8.x** file,
```
$ ./ps2lrz -i lrzip-next.git.tar.lrz
Showing file info only
lrzip-next.git.tar.lrz is an lrzip version 0.8 file
lrzip-next.git.tar.lrz is not encrypted
lrzip-next.git.tar.lrz uncompressed file size is 13342720 bytes
Dumping magic header 18 bytes
Byte Offset      Description/Content
===========      ===================
Magic Bytes 0-3: 4C 52 5A 49 LRZI
Bytes 4-5:       LRZIP Major, Minor version: 00, 08
Bytes 6-13:      LRZIP Uncompressed Size bytes: 00 98 CB 00 00 00 00 00 
Byte  14:        MD5 Sum at EOF: yes
Byte  15:        File is encrypted: no
Byte  16:        LRZIP Filter 0
Byte  17:        LZMA Dictionary Size Byte 1A lc=3, lp=0, pb=2, Dictionary Size=33554432
```

## Build
`gcc -o ps2lrz ps2lrz.c`

Feeback welcome!

January 2023  
Peter Hyman  
pete@peterhyman.com
