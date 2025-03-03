---
layout: post
image: /icons/uniseccrypt.png
tags: system
title: What not to do with on prem virtualization
---


<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/system.png" width="200" title="system" ></a>
</div>

During intrusion tests and red teams, we have realized that more often than not, it was possible to find simple attack paths using the way local virtual machines were handled. This posts main topic revolves around one idea: **Broken Tiering**

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/loop.png)
{: refdef}

> TL;DR
> &rarr; Storing unencrypted VM backups and disks equates storing plaintext credentials
> &rarr; Managing hypervisors and EDR consoles with Active Directory often breaks the tiering
> &rarr; When storing images and backups securely, don't forget about integerity






Stay classy netsecurios.

---
What not to do with on prem virtual machines
---
