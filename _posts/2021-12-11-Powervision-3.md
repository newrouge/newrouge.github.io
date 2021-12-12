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

**DISCLAIMER: This blog is aimed towards educative purposes. In no way is it endorsing nor encouraging software piracy.**


After nearly a year of absence, it is now time to conclude this adventure. Most of what will be described here will seem out of topic if you haven't read:

* <a href="https://therealunicornsecurity.github.io/Powervision-1/">Part 1</a>
* <a href="https://therealunicornsecurity.github.io/Powervision-2/">Part 2</a>

# 1. Summary

In <a href="https://therealunicornsecurity.github.io/Powervision-1/">Part 1</a>, we decrypted and retrieved the full firmware of the programmer,  in <a href="https://therealunicornsecurity.github.io/Powervision-2/">Part 2</a>, we reverse engineered the communication protocol on the USB link. Now holding all the cards, we can achieve our primary goal, that was **bypassing the licensing system** in place!



# 2. Licensing functions

The ultimate goal of the exercice is to be able to use the PowerVision without a valid license. It can be achieved in many different ways: forging a license, or disabling the verification it is subjected to, or deleting/ignoring the VIN locks. For neophytes, the <a href="https://en.wikipedia.org/wiki/Vehicle_identification_number">Vehicle Identification Number</a> is a unique identifier stored in the <a href="https://en.wikipedia.org/wiki/Electronic_control_unit">ECU</a>. A VIN Lock is therefore essentially just a VIN stored in the programmer, which is used to ensure the device will not be used to program anything else. Here are a few sample VINs for Harley Davidson:

- 1HD1KED10HB661265 — 2017 Harley-Davidson FLHTK / ultra limited - (1.8 Li), Motorcycle - Touring
- 1HD1BFV14EB015825 — 2014 Harley-Davidson FXSB-103 Breakout (1.7 Li V2), Motorcycle - Custom
- 1HD1FC413AB618635 — 2010 Harley-Davidson FLHTCU (1584CC), Motorcycle - Touring

## 2.1 License

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
The *cmd* part here contains the command **VL**, that indicates to the PowerVision which VIN it is coupled to.Controlling the value of this field is the ultimate jackpot, as it enables to forge licenses for arbitrary VINs. The *signature*, however, is here in order to prevent exactly this. It contains the **SHA1** of the XML file, encrypted with Dynojet's private key. In order to verify the signature, the PowerVision stores the public key in an encrypted database. It then proceeds to hash the file, and performs a *memcmp* on the resulting hash, and the one obtained using decryption. Here is the overview of the license verification function:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/license_overview.png)
{: refdef}

By patching the following code segment, we can easily anticipate how the verification bypass could be implemented:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/license_memcmp.png)
{: refdef}

While reversing the license verification function, we realized that there could be many other ways to forge a license than just changing the VIN. In fact, the *cmd* field can contain several other functions than the VIN locking one, and they could probably be abused too. Also, one of the easiest ways to defeat the single VIN restriction would be creating a *dealer* license, as they are not submitted to the same constraints.

## 2.2 VIN Locks

Another way to solve our problem would be to "unmarry" the PowerVision. To do that, we can take two paths:

* Locate and modify the locks
* Patch the *get_locks* function

The first choice was quickly abandonned for the following reason: the PowerVision stores the locks in **NVRAM**. We already had experienced that issue when trying to locate the firmware encryption key, and the NVRAM can't be read directly from **/dev**

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/nvram.png)
{: refdef}

It actually uses a low-level API, developed by the hardware manufacturer (Drew Technol**o**gies). It seems to be linked to the files:

* usr/lib/libPP2534.so
* lib/modules/2.6.30/kernel/drivers/char/ermine_arm7_ldisc.ko

A guess is that we'd need the api to communicate with a kernel module, that has the capacity to read and write from the NVRAM. Sounds like a hassle, doesn't it ? We have better ways...

Let's take the lazy path, and consider the functions that interepret the results gathered from the NVRAM:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/getlocks.png)
{: refdef}

The **get_locks** function gathers data from the NVRAM api, and stores locks data in the following structure:

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

From there, it becomes quite easy to hardcode some of the values in the **get_locks** function, so that it always returns with a certain amount of free locks!

# 3. Micropatching

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

To do so, we can negate the *Branch if not equal* instruction, and replace it by *Branch if equal*:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/neg2.png)
{: refdef}

**Warning:** this is a relatively unstable way of patching. Bear in mind that the code will proceed successfully with any license presenting an **invalid** signature, but will **abort** if presented with a **valid** signature. 

# 3.3 NOP

After the license verification, the register **R4** contains a boolean, indicating whether the verification has failed or not. If it has failed, it jumps to an error handler, and aborts:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/nop1.png)
{: refdef}

By replacing the *Branch if Equal* instruction, by a NOP, we make sure this error case is never reached, and the code continues executing after *CMP/NOP* instructions:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/nop2.png)
{: refdef}

As this code is ARM (little endian), the NOP used was:

```
00 00 A0 E1 MOV R0, R0
```

# 4. Firmware update process

Now that we have a patched version of the main binary, we can package it to install it on the PowerVision. In [Part 1](https://therealunicornsecurity.github.io/Powervision-1/) we analyzed the content of **PVU** (PowerVision Update) files, they contain:

* PVU_TYPE: (firmware, recovery, tunes...)                                                                                                
* PVU_FILE: encrypted file containing
    * NEW_ROOTFS.bin: squashfs file system, readonly
    * NEW_KERNEL.bin: kernel update  
* **PVU_CERT**: update file signature (ouch)

In the code, we discovered that there is an intergrity check on the uplodaded firmware updates. The encrypted databases contain an **UPDATES_PK** entry, that is used to decrypt the **PVU_CERT** file. Of course, we could rebuild a database embedding our own key, or even bypass the check using micropatching. But again, we are lazy. While reversing the firmware update function, we discovered a **VERY** **USEFUL** tool:
```
0015B3A3 00                                ALIGN 4
0015B3A4 75 62 69 75 70 64+aUbiupdatevolDe DCB "ubiupdatevol /dev/ubi0_0 /flash/NEW_ROOTFS.BIN",0
0015B3A4 61 74 65 76 6F 6C+                               
```
Connecting with the shell we obtained previously, we were able to confirm the existence, and the purpose, of the **ubiupdatevol** binary. Like its name indicates, it is used to **write directly** on the /dev/ubi devices, which contain the squashfs file system we want to patch. The only thing needed is therefore a way to upload a file on the PowerVision device. But we **have that too**:

```
def send_file(path, content):
    pvlink = CDLL("./PVLink.dll")
    sendfile = pvlink.PVSendFile
    r = sendfile(path, len(content), content)
    if r != 0:
        print("Error")
    else:
        print("Wrote /flash/storage/rootfs_patch.sqsh")

if __name__ == "__main__":
    f = open("rootfs_patch.sqsh", rb)
    print("running...")
    send_file("updates:rootfs_patch.sqsh", f.read())
```

Now we just need to connect, and use the **ubiupdatevol** tool with the patched file we uploaded:

<asciinema-player src="/images/Dynojet/455443.cast" cols="117" rows="60"></asciinema-player>
<script src="/asciinema-player.js"></script>

This bypasses the signature verification, as we are now writing directly to the device!

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/boratgs.jpg)
{: refdef}

To summarize, the steps are:

- Patch main binary
- Copy binary to squashfs tree structure, and **keep destination file attributes**
- mksquashfs
- Send patched squashfs to the device using the PVLink api
- Connect through UART and write to the ubi volume

After a little bit of pimping, we can see that the PowerVision does print the correct "Tuning: Not Locked to vehicle" message:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/video-1639231798.gif)
{: refdef}

As some of you may have guessed, this message does not necessarily mean that we have bypassed the locks verification. In fact, it only proves that we are able to modify the firmware. To prove that our modifications have deeper implications, we can get the device's information using **pvinfo**:

```
def do_soap(request):
    pvlink = CDLL("./PVLink.dll")
    dosoap = pvlink.PVDoSoapEx
    dosoap.argtypes = [c_int, c_char_p, POINTER(c_char_p), c_char_p, c_int, c_int, c_int, c_int]
    ref = c_char_p()
    a = 0
    point = ''
    dosoap(len(request), request, byref(ref), point, 1, 5, a, a)
    return ref.value

def reqtype(typestring):
    req = "<request><type>"+typestring+"</type><ver>1</ver><summary></summary></request>"
    return do_soap(req)

if __name__ == "__main__":
    print reqtype("pvinfo")

```

And here is a comparison of the two responses (before and after patching) in JSON, because fuck XML:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/jsondiff.jpg)
{: refdef}

# 5. Conclusion

The time we spent on this analysis speaks for itself (over a year). The protections in place are quite robust and well thought, and the overall firmware's architecture is complex and interesting. The PowerVision 1 has definitely been a worthy opponent, and we had lots of fun working on it. 

This last part is mainly to show examples of software bypasses (for licenses, but also security features like anti-vm/anti-debugging functions, or even sometimes debugging) that are generic. The fact that we were able to perform them on this device is not a vulnerability in itself, but merely just the resulting possibilities of two factors:

- Being able to read and understand the firmware
- Being able to write the firmware

We encourage the readers interested in such work to report vulnerabilities and bypasses they find to the original software publishers. Good work is always valued!

**WARNING: Modifying the firmware will leave the device in an unstable state. This PoC is not intended to be reproduced, and should NEVER be againt with a real bike. It can damage the ECU, and will likely brick the Powervision.**

## References

* https://www.faxvin.com/vin-decoder/harley-davidson
* https://dynojet.zendesk.com/hc/en-us/articles/360003434773-Power-Vision-Recovery-Info


I wish to thank all of you readers, we had great feedbacks and interesting discussions over the last year about this topic. Feel free to join our discord server, and stay classy netsecurios!
 
[Part 1](https://therealunicornsecurity.github.io/Powervision-1/)
[Part 2](https://therealunicornsecurity.github.io/Powervision-2/)
