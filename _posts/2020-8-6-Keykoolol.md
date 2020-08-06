---
layout: post
title: Reverse Engineering Obfuscated Code - CTF Write-Up
---
This is a write up for one of the FCSC (French Cyber Security Challenge) reverse engineering challenges. 

It was the first time I had to deal with virtualized code, so my solution is far from being the best. Surely there were much quicker ways, but mine did get the job done.
This write-up is essentially meant for beginners in the domain of obfuscated code reverse engineering.

# Part 1: Type of challenge
This happens to be a keygen type of challenge, here are the rules (in French):

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/keykoolol.png)
{: refdef}

Basically, it is saying that you have to download a binary, that will take inputs, and much like a licensed software, will verify those inputs against each other. This is meant to mimic the way proprietary software verifies license keys.

The goal is the create a keygen: a script that will generate valid inputs to feed to the license verification algorithm.
Of course, with only an offline validation, the challenge becomes trivial (simple patch and let's goo), but you have to validate your inputs against an online version of the same binary. There are two inputs: a username, and a serial.

Executing it will yield:


```shell
 root@kali:~# ./keykoolol 
    [+] Username: toto
    [+] Serial:   tutu
    [!] Incorrect serial.
```


In those types of challenges, I would advise you to manually fuzz inputs. By sending special characters and strings with an invalid length, you might get an interesting error message. Keep in mind that the first step is the understand what the software is expecting as inputs.

But it's not going to help here :) (would be too easy)

Let's go roughly through the steps we will have to follow:
1. Download the binary
2. Disassemble it
3. Understand and implement the serial verification function
4. Implement an algorithm that, given an username, generates a corresponding serial
5. Test locally
6. Validate online
7. Get tons of points

# Part 2: ELF analysis

The file is an 16Ko ELF file.

The command `file` gives:
```
keykoolol: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, 
           interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
           BuildID[sha1]=1422aa3ad6edad4cc689ec6ed5d9fd4e6263cd72,
           stripped
```
Nothing tremendously interesting here, the sections though will reveal more interesting things (using `readelf -e`):

```
[14] .text             PROGBITS         0000000000000730  00000730
     0000000000001ce2  0000000000000000  AX       0     0     16
[16] .rodata           PROGBITS         0000000000002420  00002420
     00000000000004c0  0000000000000000   A       0     0     32
[24] .bss              NOBITS           0000000000203020  00003010
     0000000000002868  0000000000000000  WA       0     0     32
```

So `text` contains our code, but `rodata` and `bss` are quite large. 1216 bytes for `rodata` and 10Ko for `bss` ? Something smells fishy.
As a reminder, `bss` is meant for uninitialized global variables. It often contains stuff like session encryption keys and pretty much any runtime data that requires a globally shared pointer 

What is in `rodata` ?

```
00000000: 0100 0200 5b2b 5d20 5573 6572 6e61 6d65  ....[+] Username
00000010: 3a20 000a 005b 2b5d 2053 6572 6961 6c3a  : ...[+] Serial:
00000020: 2020 2000 5b3e 5d20 5661 6c69 6420 7365     .[>] Valid se
00000030: 7269 616c 2100 5b3e 5d20 4e6f 7720 636f  rial!.[>] Now co
00000040: 6e6e 6563 7420 746f 2074 6865 2072 656d  nnect to the rem
00000050: 6f74 6520 7365 7276 6572 2061 6e64 2067  ote server and g
00000060: 656e 6572 6174 6520 7365 7269 616c 7320  enerate serials 
00000070: 666f 7220 7468 6520 6769 7665 6e20 7573  for the given us
00000080: 6572 6e61 6d65 732e 005b 215d 2049 6e63  ernames..[!] Inc
00000090: 6f72 7265 6374 2073 6572 6961 6c2e 0000  orrect serial...
000000a0: 0004 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 6e18 b017 c9f5 bf08 7400 000a 3752 0a00  n.......t...7R..
000000d0: 9895 1c00 7403 0006 881c 0008 7400 000a  ....t.......t...
000000e0: 3f9e 0800 5694 1c00 ad06 180c c60f 2002  ?...V......... .
000000f0: 8802 0006 8997 0c00 7c02 080c c973 1c00  ........|....s..
00000100: 5b00 190c 7c00 0006 fa1b 0c00 f701 1000  [...|...........
00000110: a7f3 1f0c 4b19 100c fc00 0006 5a41 0c00  ....K.......ZA..
00000120: 0995 1c00 8e08 180c 280b 2602 e802 0006  ........(.&.....
00000130: 6434 7bff 050c 0002 afb4 68ff de24 f21a  d4{.......h..$..
00000140: 0588 f40c fd5c dd12 c049 df13 b982 d01d  .....\...I......
```
As expected, we can see the strings used by the binary to indicate us the validity of the entry. But what is after offset `0x000000c0` ? The data seems jibberish and not interpretable, but is it random ?

### Reverse Engineering Obfuscated Code
---
FCSC 2020
Keykoolol
500 points
---
