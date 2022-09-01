---
layout: post
title: "Hack the Box Dirty Money 2022 - Mr. Abilgate"
summary: "Solving Mr. Abilgate challenge from Hack the Box Dirty Money CTF"
date:   2022-08-31 14:00:00 -0400
categories: Reverse engineering
---

Another challenge from Hack The Box. This time, we are given an PE file, KeyStorage.exe and an encrypted file, ImportantAssets.xls.bhtbr. Assuming the binary will traverse the filesystem en encrypt some files, we can guess what function calls could be made.

> TLDR: Patch the BCryptEncrypt function pointer to BCryptDecrypt using Frida.

## Quick look
The PE file is packed with UPX, uses API hashing and got at least one anti-debugging techniques.

```
$ strings KeyStorage.exe

!This program cannot be run in DOS mode.
RichXC
UPX0
UPX1
.rsrc
3.96
UPX!
```

Upx can be used to unpack the binary, but it doesn't help that much. The main looks like this.

![Main](/assets/htb_abilgate/main.png)

The API hashing and the antidebug:

![API hashing and antidebug](/assets/htb_abilgate/antidebug.png)

I didn't want to dig more and spend more time reversing the binary and I though running it with API Monitor could help. This led to an interesting `NtOpenFile` call.

![NtOpenFile](/assets/htb_abilgate/not_found.png)

I just created all the folders and put a file in it. The binary continued its execution and cryptographic functions were eventually called.

![BCryptEncrypt](/assets/htb_abilgate/encrypt.png)

From there, we could either dump the memory, extract the encryption key, IV, algorithm used and code a function that would decrypt the xlsx... or we could just patch the function pointer to BCryptDecrypt.
This is easy to do because both functions share the same parameters in the same order!

```c
NTSTATUS BCryptEncrypt(
  [in, out]           BCRYPT_KEY_HANDLE hKey,
  [in]                PUCHAR            pbInput,
  [in]                ULONG             cbInput,
  [in, optional]      VOID              *pPaddingInfo,
  [in, out, optional] PUCHAR            pbIV,
  [in]                ULONG             cbIV,
  [out, optional]     PUCHAR            pbOutput,
  [in]                ULONG             cbOutput,
  [out]               ULONG             *pcbResult,
  [in]                ULONG             dwFlags
);
```

```c
NTSTATUS BCryptDecrypt(
  [in, out]           BCRYPT_KEY_HANDLE hKey,
  [in]                PUCHAR            pbInput,
  [in]                ULONG             cbInput,
  [in, optional]      VOID              *pPaddingInfo,
  [in, out, optional] PUCHAR            pbIV,
  [in]                ULONG             cbIV,
  [out, optional]     PUCHAR            pbOutput,
  [in]                ULONG             cbOutput,
  [out]               ULONG             *pcbResult,
  [in]                ULONG             dwFlags
);
```

## Instrumentation

It is also quite trivial to do using Frida, as it offers a way to simply replace pointers and run it like this `frida -f KeyStorage.exe -l script.js`

```js
const BCryptEncryptPtr = Module.getExportByName("Bcrypt.dll", "BCryptEncrypt");
const BCryptDecryptPtr = Module.getExportByName("Bcrypt.dll", "BCryptDecrypt");

Interceptor.replace(BCryptEncryptPtr, BCryptDecryptPtr);
```

This should give us a decrypted xls file, an thus the flag. For some reason, I wasn't able to open it in Excel, but it did work when changing the extension to xlsx.

![Flag](/assets/htb_abilgate/flag.png)
