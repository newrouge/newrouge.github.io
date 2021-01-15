---
layout: post
tags: reverse hardware
title: Hacking a Harley's Tuner - Part 2
---

Reverse Engineering a famous Harley's tuner

**NOTE: All encryption keys and passwords are fake ones made up for writing this post.**


<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/reverse.png" width="200" title="reverse" ></a>
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/system.png" width="200" title="system" ></a>
</div>


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/buffer_overflow_crop.jpg)
{: refdef}

In the previous part, we ended up downloaded the full firmware unencrypted from the console connection. Now is time to show you what we have done with it.

## Part 1: The Filex Protocol
The Filex protocol is the name of the proprietary protocol used on the USB Link port. All the Windows softwares are actually using this Filex protocol through the USB Link, to configure the PowerVision. To do so, they have to use the PVLink.dll.
### Specification and KaitaiStruct
After a few captures using [USBPcap](https://desowin.org/usbpcap/) as a Wireshark plugin, we started understanding the structure of the binary messages:
```yaml
seq:
  - id: start_byte
    size: 1
    contents: [0xf0]
  - id: type
    type: s4
    enum: type_value
  - id: param1
    type: s4
  - id: param2
    type: s4
  - id: datalen
    type: s4
  - id: seq
    type: s4
  - id: data
    size: datalen
    type: strz
    encoding: ASCII
  - id: checksum
    type: u1
  - id: end_byte
    size: 1
    contents: [0xf0]
```
The Kaitai Struct is quite simple, there is no nested data. The packet is delimited between 0xF0 bytes. There is 5 32 bits Little-Endian integers as headers, used for function types, parameters, length, and a sequence number. In the end of the packet, there is a one byte checksum before the actual 0xF0 end of packet.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/fields.jpg)
{: refdef}

Here is the structure applied to a packet sent from the WinPV.exe software. We can see that the program is running a **DELETE_FILE** operation on the PowerVision, and the file name is **params:soap_req**.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/hexview.jpg)
{: refdef}

This file is very important. On top on the Filex protocol is a SOAP API (yes yes, a SOAP API over a serial connection), and the requests are stored in **soap_req**, while the response are in **soap_resp**. At every startup of the WinPV.exe program, those files are checked and deleted if existing.

### PVLink.dll
### Buffer Overflow

## Part 2: Looting
### Root password
### Encryption Keys
