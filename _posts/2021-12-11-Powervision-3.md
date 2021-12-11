---
layout: post
tags: reverse crypto
title: Hacking a Harley's Tuner - Part 3
---

Completion of the primary objective

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/part3.jpg)
{: refdef}


<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/reverse.png" width="200" title="reverse" ></a>
   <a href="/tags#system"><img src="{{ site.baseurl }}/icons/crypto.png" width="200" title="crypto" ></a>
</div>

**DISCLAIMER: This blog is aimed towards educative purposes. In no way it is endorsing nor encouraging software piracy**

After nearly a year of absence, it is now time to conclude this adventure. Most of what will be described here will seem out of topic if you haven't read:

* <a href="https://therealunicornsecurity.github.io/Powervision-1/">Part 1</a>
* <a href="https://therealunicornsecurity.github.io/Powervision-2/">Part 2</a>

# Part 1: Summary

In <a href="https://therealunicornsecurity.github.io/Powervision-1/">Part 1</a>, we decrypted and retrieved the full firmware of the programmer,  in <a href="https://therealunicornsecurity.github.io/Powervision-2/">Part 2</a>, we reverse engineered the communication protocol on the USB link. Now holding all the cards, we can achieve our primary goal, that was **bypassing the licensing system** in place!



# Part 2: Licensing functions

The ultimate goal of the exercice is to be able to use the PowerVision without a valid license. It can be achieved in many different ways: forging a license, or disabling the verification it is subjected to, or deleting/ignoring the VIN locks. For neophytes, the <a href="https://en.wikipedia.org/wiki/Vehicle_identification_number">Vehicle Identification Number</a> is a unique identifier stored in the <a href="https://en.wikipedia.org/wiki/Electronic_control_unit">ECU</a>. A VIN Lock is therefore essentially just an VIN stored in the programmer, used to ensure the device will not be used to program anything else. Here are a few sample VINs for Harley Davidson:

- 1HD1KED10HB661265 — 2017 Harley-Davidson FLHTK / ultra limited - (1.8 Li), Motorcycle - Touring
- 1HD1BFV14EB015825 — 2014 Harley-Davidson FXSB-103 Breakout (1.7 Li V2), Motorcycle - Custom
- 1HD1FC413AB618635 — 2010 Harley-Davidson FLHTCU (1584CC), Motorcycle - Touring

## 2.1: License

For the Dynojet PowerVision 1, a license file is something of the form:

```XML
<PVLicense>
   <Name>
      PV1
   </Name>
   <Company>
      UNISEC
   </Company>
   <Email>
      none
   </Email>
   <LicenseCode>
      1234
   </LicenseCode>
   <ExpireVer>
      2.1.0
   </ExpireVer>
   <Cmd>
      VL:<VIN>
   </Cmd>
   <Signature>
q8EgYRN+XZ/88wEyYfAOQEkZ7GPoV/JbtvuYYsUEOhEWH1cyN1i9OvHPyaj945+fgILJUEJNaGgM15YUwtlsJQ==
   </Signature>
</PVLicense>
```
The *cmd* part here contains the command **VL**, that indicates to the PowerVision which VIN it is married to. Controling this field means being able to forge signatures for arbitrary VINs, so it would be jackpot. The *signature*, however, is here in order to prevent exactly this. It contains the **SHA1** of the XML file, encrypted with Dynojet's private key. In order to verify the signature, the PowerVision stores the public key in an encrypted database. It then proceeds to hash the file, and perform a *memcmp* on the resulting hash, and the one obtained using decryption. Here is the overview of the license verification function:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/license_overview.png)
{: refdef}

By patching the following code segment, we can easily anticipate how the verification bypass could be implemented:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/license_memcmp.png)
{: refdef}

While reversing the license verification function, we realized that there could be many other ways to forge a license than just changing the VIN. In fact, the *cmd* field can contain several other functions than the VIN locking one, and they could probably be abused too. Also, one of the easiest ways to defeat the single VIN restriction would be creating a *dealer* license, as they are not submitted to the same constraints.

## 2.2: VIN Locks

Another way to solve our problem would be to "unmarry" the PowerVision. To do that, we can take two paths:

* Locate and modify the locks
* Patch the *get_locks* function

The first choice was quickly abandonned for the following reason: the PowerVision stores the locks in **NVRAM**. We already had experienced that issue when trying to locate the firmware encryption key, and the NVRAM can't be read directly from **/dev**

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/nvram.png)
{: refdef}

It actually uses a low-level API, developped by the hardware manufacturer (Drew Technol**o**gies). It seems to be linked to the files:

* usr/lib/libPP2534.so
* lib/modules/2.6.30/kernel/drivers/char/ermine_arm7_ldisc.ko

A guess it that we'd need the api to communicate with a kernel module, that has the capacity to read and write from the NVRAM. Sounds like a hassle, doesn't it ? We have better ways...

Let's take the lazy path, and actually handle the functions that interepret the results gathered from the NVRAM:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/getlocks.png)
{: refdef}

The only trick with this function is that it actually acts more like a **procedure**, it modifies a structure by side effect.

```
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 lockptr         struc ; (sizeof=0x10, mappedto_46)
00000000                                         ; XREF: pvinfo/r
00000000 active_mask     DCD ?
00000004 used_mask       DCD ?
00000008 first_unused    DCD ?
0000000C total           DCB ?
0000000D used            DCB ?
0000000E free            DCB ?
0000000F max             DCB ?
00000010 lockptr         ends
00000010
00000000 ; ---------------------------------------------------------------------------
```

Hopefully, using different functions that parse the result from *get_locks*, we can get a more precise idea of the structure and it's contents. From there, it becomes quite easy to hardcode some of the values in the function, so that it always returns with a certan amount of free locks!

# Part 3: Micropatching

These are basic patching tricks used when in certain conditions. It is far from exhaustive.

# 3.1 Unconditional jump

When getting the amount of active VIN locks, we would like the code to always jump to the block "Tuning: Not Locked to vehicle". 

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/uncond.png)
{: refdef}

In order to do that, we replace the *Branch if equal* instruction by an unconditional *Branch* instruction:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/uncond2.png)
{: refdef}


# 3.2 Condition negation

When verifying the license's signature, we would like the code to always jump to the "Verified: YES" location:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/neg1.png)
{: refdef}

To do so, we can negate the *Branch if not equal* instrucction, and replace it by *Branch if equal*:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/neg2.png)
{: refdef}

**Warning:** this is a relatively unstable way of patching. Bear in mind that the code will proceed successfully with any license presenting an **invalid** signature, but will **abort** if presented with a **valid** signature. 

# 3.3 NOP

After the license's verification, the register **R4** contains a boolean, indicating whether the verification has failed or not. If it has failed, it jumps to an error handler, and aborts:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/nop1.png)
{: refdef}

By replacing the *Branch if Equal* instruction, by a NOP, we make sure this error case is never reached, and the code keeps executing after the comparison:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/nop2.png)
{: refdef}

As this code is ARM (little endian), the NOP used was:

```
00 00 A0 E1 MOV R0, R0
```

# Part 4: Firmware update process


## References

* https://www.faxvin.com/vin-decoder/harley-davidson




I wish to thank all of you readers, we had great feedbacks and interesting discussions over the last year about this topic. Feel free to join our discord server, and stay classy netsecurios!
 
[Part 1](https://therealunicornsecurity.github.io/Powervision-1/)
[Part 2](https://therealunicornsecurity.github.io/Powervision-2/)
