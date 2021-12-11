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



After nearly a year of absence, it is now time to conclude this adventure. Most of what will be described here will seem out of topic if you haven't read:

* <a href="https://therealunicornsecurity.github.io/Powervision-1/">Part 1</a>
* <a href="https://therealunicornsecurity.github.io/Powervision-2/">Part 2</a>

# Part 1: Summary

In <a href="https://therealunicornsecurity.github.io/Powervision-1/">Part 1</a>, we decrypted and retrieved the full firmware of the programmer,  in <a href="https://therealunicornsecurity.github.io/Powervision-2/">Part 2</a>, we reverse engineered the communication protocol on the USB link. Now holding all the cards, we can achieve our primary goal, that was **bypassing the licensing system** in place!



# Part 2: Licensing functions

The ultimate goal of the exercice is to be able to use the PowerVision without a valid license. It can be achieved in many different ways: forging a license, or disabling the verification it is subjected to, or deleting/ignoring the VIN locks. For neophytes, the <a href="https://en.wikipedia.org/wiki/Vehicle_identification_number">Vehicle Identification Number</a> is a unique identifier stored in the <a href="https://en.wikipedia.org/wiki/Electronic_control_unit">ECU</a>. A VIN Lock is therefore essentially just an VIN stored in the programmer, used to ensure the device will not be used to program anything else.

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

## 2.3: NVRAM 

# Part 3: Micropatching

# Part 4: Firmware update process


## References

[This post](https://blog.senr.io/blog/jtag-explained) gave me the idea for switching to single user mode in the boot parameters.

## In the next episode

- Firmware reverse engineering and emulation (focus on the USB Link proprietary protocol)
- Loot (passwords, encryption keys...)
- Buffer overflow

[Part 2](https://therealunicornsecurity.github.io/Powervision-2/)

I wish to thank all of you readers, we had great feedbacks and interesting discussions over the last year about this topic. Feel free to join our discord server, and stay classy netsecurios!
 
