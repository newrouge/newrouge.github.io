---
layout: post
tags: crypto reverse hardware system
title: Hacking a Harley's Tuner
---

Finding my ways to the firmware of a famous Harley tuner

**NOTE: All encryption keys and passwords are fake ones made up for writing this post.**

<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/reverse.png" width="200" title="reverse" ></a>
   <a href="/tags#system"><img src="{{ site.baseurl }}/icons/system.png" width="200" title="system" ></a>
   <a href="/tags#system"><img src="{{ site.baseurl }}/icons/hardware.png" width="200" title="hardware" ></a>
   <a href="/tags#system"><img src="{{ site.baseurl }}/icons/crypto.png" width="200" title="crypto" ></a>
</div>

# Part 1: What is a tuner

A tuner is a little device supposed to be plugged to a bike. It is meant to configure the on board computer in order to optimize fuel to air ratios and other parameters. It is known to be used to lift engine power restrictions, or optimize fuel consumption. Though I am pretty sure a real biker will have much better words to describe how it can be used.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/dynojet.jpg)
{: refdef}

The model studied here is a Power Vision for Harley Davidson, by Dynojet. The hardware is a Bobcat Revision D by Drew Technologies (there is a typo on the PCB, it is actually written Drew *Technoligies*).

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/drewtech.jpg)
{: refdef}

# Part 2: Getting the firmware
## 2.1: Analyzing the tools

The tuner is supposed to be configured while being connected to a computer. It has a mini-USB input next to the CAN Bus (which is the one supposed to be connected to the bike's on board computer). The tools used to configure it are free to download on Dynojet's website.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/wintools.png)
{: refdef}

The installed windows tools contains the following binaries:
* WinPV.exe: the main software with the GUI
* PVUpdateClient.exe: updater, in charge of downloading new firmwares and copying them through the USB link
* RecoveryTool.exe: called exclusively by the PVUpdateClient, it is in charge of flashing the recovery part of the firmware
* PVLink.dll: in charge of the communication through the serial port, very important

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/pv_files.png)
{: refdef}

Now, our goal is to get the firmware so we can start reversing. Checking on youtube tutorials and thewaybackmachine, we can see that firmware used to be available directly on dynojet's website, under the **firmware** section, which is now empty. We find our happiness by running the PVUpdateCLient.exe, and wireshark simultaneously.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/pvupdate.png)
{: refdef}

The wireshark capture shows plaintext HTTP going to *dynojetpowervision.com*, and checking for available firmware files. There is no real protection here, just the User-Agent you are supposed to be using is "PVUpdateClient", otherwise, the files remain hidden.  
Using **curl**, we get the filenames we are looking for:
```bash
 curl -v -A PVUpdateClient http://dynojetpowervision.com/downloads/PowerVisionVersions.xml
*   Trying 52.183.62.164:80...
* TCP_NODELAY set
* Connected to dynojetpowervision.com (52.183.62.164) port 80 (#0)
> GET /downloads/PowerVisionVersions.xml HTTP/1.1
> Host: dynojetpowervision.com
> User-Agent: PVUpdateClient
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: text/xml
< Last-Modified: Mon, 09 Nov 2020 18:35:22 GMT
< Accept-Ranges: bytes
...
 <PVSystemUpgrade.1.1 ver="1.0.1 1.0.1" package="PV_SYSTEMUPGRADE-1.0.1-631.pvr"/>
 <PVFirmware.1.1 ver="2.0.47-1613" package="PV_FIRMWARE-2.0.47-1613.pvu" />
 <PVTuneDB.1.1 ver="0.0.10.11" package="PV_TUNEDB-0.0.10.11.pvu" />
...
```

We start focusing the **FIRMWARE** and **SYSTEM_UPGRADE** files, as they are the most likely to contain what we are interested in. We download them using **wget**, and trouble begins here:
```bash
mishellcode@unisec:~/powervision$ unzip PV_SYSTEMUPGRADE-1.0.1-631.pvr                                                  
Archive:  PV_SYSTEMUPGRADE-1.0.1-631.pvr                                                                                
[PV_SYSTEMUPGRADE-1.0.1-631.pvr] PVRecoveryInfo.xml password: 
```

```bash
mishellcode@unisec:~/powervision$ unzip PV_FIRMWARE-2.0.47-1613.pvu                                                     
Archive:  PV_FIRMWARE-2.0.47-1613.pvu                                                                                    
extracting: PVU_TYPE                                                                                                    
extracting: PVU_CERT                                                                                                     
inflating: PVU_FILE                                                                                                   
mishellcode@unisec:~/powervision$ file PVU_FILE                                                                        
PVU_FILE: openssl enc'd data with salted password                                                                            
```

The **SYSTEM_RECOVERY**, that we will call PVR file, is a password protected archive, and the **FIRMWARE** file, named PVU, is actually encrypted using openssl.Also, the PVU_CERT file indicates that there might be an integerity check performed on the PVU_FILE.  

I'll skip the details, but since the PVR file is written in plaintext on the device, it was obvious that one of the tools (in this case RecoveryTool.exe) had the password somewhere. A bit of reverse engineering later, we get a password "POWERVISION_RECOVER_3456789Z". Though I won't explain the whole thing here, this password is actually kind of hidden. It is not hardcoded but instead, some loops go over integer values to generate the ending pattern of the password, and then concatenate a capital letter to it. There is a clear intention to hide this from badly intentioned users, and thats usually a sign we're on the right track.

### Recovery File Contents

```bash
nandflash_bobcat.bin: data                                                                                              
PVRecoveryInfo.xml:   exported SGML document, ASCII text, with CRLF line terminators                                    
u-boot.bin:           data                                                                                              
uImage:               u-boot legacy uImage, Bobcat-577, Linux/ARM, OS Kernel Image (Not compressed), 828996 bytes, Thu Feb  3 14:44:52 2011, Load Address: 0x20008000, Entry Point: 0x20008040, Header CRC: 0x5EDBBE36, Data CRC: 0xD026D2D5 
````

The recovery file is a u-boot image with a Kernel image. The entropy of the files indicates that parts of them are encrypted. Also, the presence of *at91bootstrap* file indicates we are in presence of a SAM AT 91 board, which can use secure boot. Damned. Though we can get one information from those files: the processor type is  **SAM926X**  
Browsing the internet, we also can find this forum post, where a Drew Technoligies employee asks information about this very same family of processors (specifically, the SAM9260-EK): https://lists.denx.de/pipermail/u-boot/2011-June/093651.html

### Update File

Since the update file is encrypted, we can formulate two hypothesis:
* The firmware is stored encrypted, and decrypted at runtime. That might be slow, but since the board supports secure boot, it is viable hypothesis.
* The firmware is stored unencrypted, only the updates are encrypted. The update process decrypts the PVU_FILE, and replaces the running firmware. Would be nice, wouldn't it ?

## 2.2: Physical setup

A quick and dirty win is always to desolder the memory chip to get the firmware. But in that case, it is a bit more complicated. The entire PCB was molded in a plastic protection, probably for sealing against humidity.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/mold1.jpg)
{: refdef}

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/mold2.jpg)
{: refdef}

I had to cut it open to see the actual PCB:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/open_pcb.jpg)
{: refdef}

And, by looking closely, we can spot 4 pins with written **DEBUG** over it!

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/ports.jpg)
{: refdef}

So we connect to it using UART to USB adapter, and fireup minicom.

```
ROMBoot
Welcome to bobcat
bocat login:
```
Problem is, the shell is password protected, and even after days of bruteforcing (using [this tool](https://github.com/FireFart/UARTBruteForcer/blob/master/uart.py), no password was found.   Also, U-Boot is set as quiet and there is now way from this shell to interact with the boot sequence.  
One track remains unexplored: the **RECOVERY MODE**

### Recovery Mode

Messing around with the RecoveryTool.exe, we found that there is a recovery mode for the device. It is activated by pressing the power button while plugin in the USB link.
