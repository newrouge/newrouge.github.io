---
layout: post
tags: crypto reverse hardware system
title: Hacking a Harley's Tuner
---

Finding my ways to the firmware of a famous Harley tuner

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
## 2.2: Physical setup
