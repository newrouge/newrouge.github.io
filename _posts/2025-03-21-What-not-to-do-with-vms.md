---
layout: post
image: /icons/uniseccrypt.png
tags: system
title: What not to do with on prem virtualization
---

Common misconfigurations in on prem VM environments <br>

During intrusion tests and red teams, we have realized that more often than not, it was possible to find virtual machines artifacts, active profiles, unencrypted backups... This posts main topic revolves around one idea: **Broken Tiering**

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/loop.png)
{: refdef}

Why does it matter you may ask ? For one thing, the hierarchy of privileges is supposed to be a tree. So if you find a loop in a tree it's never a good sign. But enough with the theory. We will see here examples showing how to exploit common misconfigurations in virtualized environments. Note that they are not specific to one technology (VMWare, HyperV, ...) and may pretty much apply to any of them.

> TL;DR
> &rarr; Storing unencrypted VM backups and disks equates exposing plaintext credentials<br>
> &rarr; Managing hypervisors and EDR consoles within Active Directory often breaks the tiering<br>
> &rarr; When using disk images, user profiles or backups, don't forget about integrity<br>

# 0. Intro: Tiering

For those unfamiliar with the tiering in Active Directory, here is how it works:

* Tier 0: Contains anything linked to Domain Controllers and Domain administrators. Basically, it should only be accessed when making changes at the domain level (password policies, GPOs, ...)
* Tier 1: Meant mostly for server's management. It contains less critical assets than the previous one, but will likely represent a higher risk at the business level.
* Tier 2: Workstations, phones, printers

This security model is made in such a way that administrators separate roles and account. This ensures, for example, that compromising a laptop, and all accounts logged into it, will not immediately lead to the fall of the castle.

# 1. Unencrypted VM storage

This one is the most commonly seen.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/scrap.png)
{: refdef}

The virtual machines backups, snapshots, images, virtual disks, all contain **secrets**. The image above tries to summarize which kind of secrets are generally stored in those files, while being loosely based on a Krebs article [Krebs article](https://krebsonsecurity.com/2012/10/the-scrap-value-of-a-hacked-pc-revisited/).

It is important to note that any local authentication secret, application configuration, api token, used in a virtual system, will possibly be available in a snapshot. Evidently, exposing those backups and virtual disks (which are just binary files, sometimes tedious to parse but still **files**) on a network with no or weak authentication and access control poses a problem.

For instance, a very common attack path for privilege escalation within a network containing virtual systems would follow these steps:

* Identify Hypervisors
* Identify shares containing virtual machines drives and images
    * It can be done by looking for specific extensions (eg. vhdx, qcow2, ...)
* Mount/read the volumes
    *  for .vhdx, using libguestfs: `guestmount --add vm.vhdx --inspector --ro /mnt/vm/ `
    *  for .qcow2: (adjust the partition number to match the main system's one)
```bash
modprobe nbd max_part=8
qemu-nbd --connect=/dev/nbd0 vm.qcow2
mount /dev/nbd0p1 /mnt/vm/
```




Stay classy netsecurios.

---
What not to do with on prem virtual machines
---
