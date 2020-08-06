---
layout: post
title: Reverse Engineering Obfuscated Code - CTF Write-Up
---
This is a write up for one of the FCSC (French Cyber Security Challenge) reverse engineering challenges. It was the first time I had to deal with virtualized code, so my solution is far from being the best. Surely there were much quicker ways, but mine did get the job done.
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

```shell
  keykoolol: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, 
             interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
             BuildID[sha1]=1422aa3ad6edad4cc689ec6ed5d9fd4e6263cd72,
             stripped
```

### Reverse Engineering Obfuscated Code
---
FCSC 2020
Keykoolol
500 points
---
