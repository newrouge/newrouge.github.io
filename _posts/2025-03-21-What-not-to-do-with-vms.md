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

> TL;DR<br>
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

and poof, the local Windows secrets are readable from a Linux machine:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/poof.png)
{: refdef}

This, coupled with Windows systems sharing the same local passwords, can be **devastating**.

# 2. Exploiting broken tiering

As mentionned earlier, hypervisors should not host VMs with a higher tier than themselves. Here is why:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/tiering.png)
{: refdef}

It creates a privilege escalation from tier 1 to tier 0. It is usually easily exploitable, following similar same steps as before, but with a different ending:

* Identify the hypervisors
* Identify the ones hosting a Domain Controller
* Generate a backup image
* Decrypt the NTDS.DIT file

But during audits, we have mostly used this loop for another purpose: extending the attack **outside of Active Directory**. For instance, on a large network, after administrative access to all the systems in Active Directory, what is left to do ? Auditing network equipments (switches, WiFi APs), accessing surveillance cameras, getting a root shell on Linux servers... <br>

Well, with an EDR, it can be actually made simpler, as it is often possible to execute commands on all local running agents (even Linux ones) from the main console:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/edr.png)
{: refdef}

And yes, an EDR is a security tool, but any additional component **increases the attack surface**.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/isolate.png)
{: refdef}

In order to make sure these elevations do not happen, it is necessary to **isolate the hypervisors for sensitive systems**.


# 3. Active backdooring

This one is a variant of the first point, but in this case we target an active session of a user. In this case, instead of browing the virtual machines artifacts for reusable secrets in the hope they are still relevant, we backdoor an active system to steal the user's sessions:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/bd.png)
{: refdef}

One concrete example of this attack, that can be easily implemented using the multidrop plugin from metasploit framework:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/multidrop.png)
{: refdef}

Simply by replacing or adding static files containing a UNC path on the desktop of the victim is enough to steal an active Active Directory session, and replay it on the domain.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/bd2.png)
{: refdef}

While there is a lot of countermeasures to this (protected users, SMB signing, ...), the best practice to highlight here still concerns access control and integrity for virtual systems images.

# 4. Underrated problem ?

We see this everywhere. The more complex a system is, the more likely things like this will appear. And knowing that HyperV does not even natively support disks and snapshots encryption, it becomes very evident that a lot of system administrators are not even aware of the issue.

One potential leaad that needs more investigation is the ability to omit certain files and folders from the snapshots. For example, not including SAM, nor SECURITY or NTDS.DIT files from VHDX files would greatly improve the security of on premise systems. Yet, this is, once again, not supported by HyperV.



Stay classy netsecurios.

---
What not to do with on prem virtual machines
---
