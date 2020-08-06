---
layout: post
title: Reverse Engineering Obfuscated Code - CTF Write-Up
---
This is a write up for one of the FCSC (French Cyber Security Challenge) reverse engineering challenges. I was the first time I had to deal with virtualized code, so my solution is far from being the best, surely there were much quicker ways, but mine did get the job done.
This write-up is essentially meant for beginners in the domain of obfuscated code reverse engineering.

#Part 1: Type of challenge
This happens to be a keygen type of challenge, here are the rules (in French):
![_config.yml]({{ site.baseurl }}/images/keykoolol/keykoolol.png)

Basically, it is saying that you have to download a binary, that will take inputs, and much like a licensed software, will verify those inputs against each other. This is meant to mimic the way proprietary software verifies license keys. The goal is the create a keygen: a script that will generate valid inputs to feed to the license verification algorithm.
Of course, with only an offline validation, the challenge becomes trivial (simple patch and let's goo), but you have to validate your inputs against an online version of the same binary.
There are two inputs: a username, and a serial.
Executing it will yield:
```shell
 root@kali:~# ./keykoolol 
    [+] Username: toto
    [+] Serial:   tutu
    [!] Incorrect serial.
```
### Reverse Engineering Obfuscated Code
---
FCSC 2020
Keykoolol
500 points
---
