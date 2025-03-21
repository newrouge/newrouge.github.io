---
layout: post
image: /icons/uniseccrypt.png
tags: system
title: What not to do with on prem virtualization
---

Common misconfigurations in on prem VM environments <br/>

During intrusion tests and red teams, we have realized that more often than not, it was possible to find simple attack paths using the way local virtual machines were handled. This posts main topic revolves around one idea: **Broken Tiering**

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/loop.png)
{: refdef}

Why does it matter you may ask ? For one thing, the hierarchy of privileges is supposed to be a tree. So if you find a loop in a tree it's never a good sign. But enough with the theory. We will see here examples showing how to exploit common misconfigurations in virtualized environments. Note that they are not specific to one technology (VMWare, HyperV, ...) and may pretty much apply to any of them.

> TL;DR
> &rarr; Storing unencrypted VM backups and disks equates exposing plaintext credentials
> &rarr; Managing hypervisors and EDR consoles within Active Directory often breaks the tiering
> &rarr; When using disk images, user profiles or backups, don't forget about integrity

# 0. Intro: Tiering

For those unfamiliar with the tiering in Active Directory, here is how it works:

* Tier 0: Contains anything linked to Domain Controllers and Domain administrators. Basically, it should only be accessed when making changes at the domain level (password policies, GPOs, ...)
* Tier 1: Meant mostly for server's management. It contains less critical assets than the previous one, but will likely represent a higher risk at the business level.
* Tier 2: Workstations, phones, printers

This security model is made in such a way that administrators separate 




Stay classy netsecurios.

---
What not to do with on prem virtual machines
---
