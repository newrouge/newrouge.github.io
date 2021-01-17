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
The Kaitai Struct is quite simple, there is no nested data. The packet is delimited between 0xF0 bytes. There is 5 32 bits Little-Endian integers as headers, used for function types, parameters, length, and a sequence number. In the end of the packet, there is a one byte checksum before the actual 0xF0 end of packet.  Of course, to be able to shoot packets, you need to be able to generate valid checksums. But we do not need it yet, because we have an API ready for use.

### PVLink.dll

The good thing with DLL's is that they export symbols even if they are stripped.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/pvlink_funcs.png)
{: refdef}

The great thing here is that we can very quickly write our own code to use available functions used by the Windows tools. All we need is to plug the PowerVision, and use the PVLink.dll. The first thing any pentester has in mind when given a function that has file system read capacities is to browse what is accessible, and what is not. To do this, we used the **PVReadDir** function, and fuzzed the directories names using a directory list, like [this one]
(https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-big.txt) for example. The corresponding C code:

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
    8 is a file
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
    4 is a folder

    .. is a folder !!
    
    debug033:001D269C db    4
    debug033:001D269D db    0
    debug033:001D269E db    0
    debug033:001D269F db    0
    debug033:001D26A0 db  2Eh ; .
    debug033:001D26A1 db  2Eh ; .
    debug033:001D26A2 db    0
```
Concerning the *mode* integer, I'm absolutely not sure it has anything to do with an actual mode (r, w), I just know the value it is supposed to be equal to from previous captures.  
Since then I've learned it is also quite simple to use a DLL with Python:

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
 - logs: you can gues what is in there

The problem is that the format for files and folders access is **folder:file**, and you can't specify more than one folder. For example, the license file located in *updates/licenses/license.txt* is not accessible because you would have to write **updates:licenses:license.txt**.  
The Filex API is actually pretty well written and protects against read and writes in folders that the user is not supposed to access. But by fuzzing it a bit, we discovered two very interesting things:
 - A function available can actually execute a shell command on the PowerVision
 - The *CLEAN_PATH* function that protects against directory traversals contains a buffer overflow

### Function Types

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
 
 Now we can go over all the values, and when we reached the function index **0x16**, we received a very interesting result from the PowerVision:
 ```
 Invalid cmd string
 ```
 We liked that.  
 This is quite common to see developper tools left in products like this. Often the devs would need a quick shell access for debug. After many attempts, I did not succeed in executing any PoC. Something was off. Months later, when I got my hands on the firmware, I could then reverse the function supposed to execute the shell command:
 
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

What do you mean, TODO ???  
It seems the function is actually implemented as we can see a call to **system** without any cross-reference:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/Dynojet/system_xref.png)
{: refdef}

My guess would be they never changed the log message, but the CFILE_DO_COMMAND is implemented. Probably they just removed it's call from the release version.  

Anyway, after obtaining the firmware (see [part 1](https://therealunicornsecurity.github.io/Powervision-1/)), we finally obtained the full list of functions supported by the Filex protocol, and here is the complete Kaitai Struct with the enums:

```yaml
meta:
  id: filex_msg
  endian: le
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

### Buffer Overflow

## Part 2: Looting
### Root password
### Encryption Keys
