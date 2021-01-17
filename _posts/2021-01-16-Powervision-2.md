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

The great thing here is that we can very quickly write our own code to use available functions used by the Windows tools. All we need is to plug the PowerVision, and use the PVLink.dll. The first thing any pentester has in mind when given a function that has file system read capacities is to browse what is accessible, and what is not. To do this, we used the **PVLinkReadFile** function, and fuzzed the directories names using a directory list, like [this one]
(https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-big.txt) for example. The corresponding C code:

```C
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

Since then I've learned it is also quite simple to use a DLL with Python:

```Python
from ctypes import *
def read_dir(path):
    pvlink = CDLL("./PVLink.dll")
    readdir = pvlink.PVReadDir
    nbfolders = c_int(0)
    mode = 0x400
    res = readdir(path, byref(dest), mode, byref(nbfolders))
    return res

def get_size(path):
    pvlink = CDLL("./PVLink.dll")
    getsize = pvlink.PVGetFileSize
    res = c_int(0)
    getsize(path, byref(res))
    return res

def read_file(path):
    pvlink = CDLL("./PVLink.dll")
    readfile = pvlink.PVReadFile
    readfile.argtypes = [c_char_p, c_char_p, c_int, POINTER(c_int)]
    dest = ''
    length = c_int()
    buf = ''
    size = get_size(path)
    readfile(path, dest, size, byref(length))
    return length.value
```

Concerning the *mode* integer, I'm absolutely not sure it has anything to do with an actual mode (r, w), I just know the value it is supposed to be equal to from previous captures.

### Buffer Overflow

## Part 2: Looting
### Root password
### Encryption Keys
