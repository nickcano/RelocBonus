# Reloc Packer Samples

This repository contains multiple different samples which can be used to test detection of the RelocBonus relocations-based packer. They are safe hello world applications, not harmful or malware.

**These samples are meant to run on Windows 7**. If you want to run on Windows 8 or 10, you must properly configure some execution policies. Here is a `.reg` template. You must replace `NAME_OF_EXE` with the name of the executable (file name is fine, do not use full path) you want to configure, and you must do this for each sample you use.

```
 [HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NAME_OF_EXE]
 "MitigationAuditOptions"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 "MitigationOptions"=hex:00,01,22,00,00,00,00,00,00,00,00,00,00,00,00,00
```

# Normal Samples

Samples prefixed with `normal-` are not packed using relocations. Before describing these samples, let me define a term:

`fixup` - The act of overwriting `ImageBase` of the in-memory the PE Header to match the base address of the executable in memory, which can be used as an evasion for runtime detection.

All of normal samples are "hello world" applications, with a few differences:

- `normal-nofixup.exe` has no unique behavior
- `normal-runtimefixup` does fixup inside of `EntryPoint` function

# Reloc Samples

These samples are variations of the normal samples that have been packed using RelocBonus. They **should** trigger detection.

`reloc-nofixup.exe` is the simplest sample with no fixup. Created with
```
reloc.exe --section=.text --section=.data normal-nofixup.exe reloc-nofixup.exe
```


`reloc-runtimefixup.exe` has fixup, but only inside of `EntryPoint`. Created with
```
reloc.exe --section=.text --section=.data normal-runtimefixup.exe reloc-runtimefixup.exe
```


`reloc-deltafixup.exe` has fixup, done by the Windows Loader during the relocations stage. This will almost certainly evade any post-reloc checks, but **it requires memory write-protection to be off**. This will certainly never be the case, though there is a trick to decrease section align and map a RW section on the same page as the header (Corkami figured this out, not me), causing a writeable header. This sample does not use that trick. Even though this sample really shouldn't run, you can catch the access violation in a debugger, change the page protection, and execute again to see the attack actually work. Created with 
```
reloc.exe --section=.text --section=.data normal-nofixup.exe reloc-deltafixup.exe --fixupBase
```