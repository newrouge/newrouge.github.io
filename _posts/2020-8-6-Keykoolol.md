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

Let's extract `rodata` segment using `dd`, and analyze its entropy with `binwalk -E`:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/zoom_ent.png)
{: refdef}

`rodata`'s entropy seems to be around 0.894; this is far not enough to qualify as random data. Though you probably already noticed that, in the sample, there were distingushable patterns. The `NULL` byte is very recuring, also the pattern `0006` appears four times, and `0c00` appears twice.

For instance, this is what the entropy of random data should look like:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/max_ent.png)
{: refdef}

It's slightly above 0.97, so there is a noticeable difference with the previous value.

# Part 3: Binary disassembly

Let's quickly examine the `main` function of the binary:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/main.png)
{: refdef}

We can see a call to the function in charge of the serial's validation, and then a conditional jump that will either print a valid response, or a negative one. There is no surprise here, we also can see those strings at the beginning of `rodata`.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/zoom_main.png)
{: refdef}


The interesting point here is that, if there was no online check (and that is a likely scenario with proprietary software), getting a valid prompt is ast trivial as replacing a 0x74 JZ with a 0x75 JNZ after the validation function returns. But we will address micropatching in another post.

So now, to the main part ! Let's reverse this `check_serial` function.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/check_serial.png)
{: refdef}

grazpfo#$eq!!!


OK I'm assuming that if you are still reading this it is because you are used to seeing horrible things in IDA (and I have come to learn since that this one is actually a nice one...).

Analyzing it's parameters is going to help us understand what this is doing. It is taking the variable I named `RO_DATA_ARRAY` as an argument:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/ro_data.png)
{: refdef}

Guess who's back ? It is indeed the segment we computed the entropy of earlier. `RO_DATA_ARRAY` is copied (0x400 bytes) in the `bss` (keep that in mind, it will make sense later).
I will refer to the offset of `RO_DATA_ARRAY`'s copy in the `bss` by BSS_IR_ARRAY.

The main part of the validation function is actually a loop over all the values of this array, taken as dwords (4 bytes) and checking the value of the least significant byte.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/opcodes.png)
{: refdef}

It is a 256 cases switch-case structure, and each different value for this byte will trigger a different code execution in the validation function.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/zoom_dispatcher.png)
{: refdef}

Guess what's going on here ?

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/vm2.png)
{: refdef}

You are looking at a virtual processor, interpreting a custom byte code, also know as Intermediate Representation. The original code has been split in various basic blocks, and  translated in another higher level code.

Let's get a bit more into details:
  * Dispatcher: It is parsing the intermediate representation, and linking each opcode with the code it is supposed to represent
  * Handler: Contains the actual code executed for each instrution
  
Note the 4 branches that are put on the side by IDA, they have a very specific role: they are the only conditional jumps used by all the code. The code is somehow factorized, and that makes it a pain to place a breakpoint at a specific execution step.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/conditional.png)
{: refdef}

Please accept my most sincere apologies as can clearly not organize an IDA graph in a clean way. I know it looks terrible but it's the best I had...

Here is the IR to x86 translation for the conditional jumps:

  * 15 : jump if greater (must be lower)
  * 14 : jump if shorter (must be higher or equal)
  * 0A : jump if not zero (must be equal)
  * 09 : jump if zero (must be different)
 
Studying the IR, we start spotting coding patterns, here is an example:
 ```
    0x08401ca4 decrement r9d by 1
    0x090003d4 if r9d != 0, jump to 3d4, else, next
    0x0e210cb5 mul reg+a = c * reg+a
    0x00529386 increment int_val register
    0x180003e8 jump to 0F3554D7 (3e8)
```
This is the end of the loop that verifies the length of the input. Here we see two kinds of jumps: `08 09` is a `sub, jz`, and 18 is a `jmp`. This structure here `08 09 0e 00 18` marks the end of a for loop, with a `goto`.

The value it is initialized with is 0x100, so we know our serial should be 128 bytes long. Also, I wont be detaling it here, but the loop next to this one is checking every char in the serial against the regexp [0-9a-fA-F]*. So the actual length of the serial is 0x50, as we are supposed to input an hex encoded value

Doing this we learn two important things about the virtual machine:
1. The IR syntax
2. It's macroscopic behaviour

Regarding the IR syntax, I did not completely understand all the instructions (00 to FF) but here is an example of IR syntax:
Some instructions are in the form: 
  * iiaccxxx (stored 0xXXCXACIII
  where:  
  * ii is the opcode (1 byte)
  * rax <= a, dest address, located at BSS_IR_ARRAY+rax*4 (4 bits)
  * rcx <= cc, source address, located at BSS_IR_ARRAY+rcx*4 (1 byte)
  * xxx is the next instruction's address (12 bits)
  

Addresses resolved by parameters a and c are in the `bss` section. There is a reason for that:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/keykoolol/vm_map.png)
{: refdef}

The `bss` actually contains the stack of our virtual machine ! And the part right before the beginning of the stack is understood by IDA as a section containing 2 bytes values, they are our registers !

Also `ro_data` is supposed to contain the code, but why copy the code to the stack then ? The answer lies is the next level of obfuscation: the code is self-modifying, hence the write permission requirement.
Here is an example of a code block that is XORed:
```
0x1e53403a x l1' = enc(l6, l1)      | 0xca90f29b   
0x00303373                          | 0xd4f381d2
0x0c340d94                          | 0xd8f7bf35
0x00462b98                          | 0xd4859939
0x0c410a96                          | 0xd882b837
0x00575618                          | 0xd494e4b9
0x0c5508f0                          | 0xd896ba51
```

Right column contains the IR as it is in the `ro_data` segment, and left column is obtained after a XOR with 0xA1B2C3D4. So the opcodes d8, d4 etc are actually fake instructions sending you on a wrong path. They are dead code.

There are three steps of code XORing, pretty easily detectable once you were tricked by the first one, and after deobfuscating all the IR, here are the macro steps we obtain:
 ** STEP1: verify serial charset
 ** STEP2: hash username
 ** STEP3: xor instructions with C1D2E3F4
 ** STEP4: newly created instructions: 0x50 loop
 ** STEP5: decode new instructions with A1B2C3D4
 ** STEP6: encrypt 32 rounds of AES
 ** STEP7: decode instructions with AABBCCDD
 ** STEP8: loop over serial and verify value byte per byte


### Reverse Engineering Obfuscated Code
---
FCSC 2020
Keykoolol
500 points
---
