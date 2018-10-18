# RelocBonus

RelocBonus is an obfuscation tool for Windows which instruments the Windows Loader into acting as an unpacking engine.

I gave a [talk](https://github.com/nickcano/RelocBonusSlides) about this tool at DEFCON 26; here is the abstract:

> The arbiters of defense wield many static analysis tools; disassemblers, PE viewers, and anti-viruses are among them. When you peer into their minds, these tools reveal their perilous implementations of PE file parsing. They assume PE files come as-is, but the Windows Loader actually applies many mutations (some at the command of the PE itself) before execution ever begins. This talk is about bending that loader to one's whim with the Relocations Table as a command spell. It will demonstrate how the loader can be instrumented into a mutation engine capable of transforming an utterly mangled PE file into a valid executable. This method starts with multiple ASLR Preselection attacks that force binary mapping at a predictable address. It then mangles the PE file, garbling any byte not required prior to relocation. Finally, it embeds a new Relocations Table which, when paired with a preselected base address, causes the loader to reconstruct the PE and execute it with ease. This isn't a packer or a POC, it is a PE rebuilder which generates completely valid, stable, and vastly tool-breaking executables. This talk will show you how this attack twists the protocols of a machine against the controls meant to protect it. It flexes on tools with various look-what-I-can-break demonstrations and, if you write similar tools, it'll make you rethink how you do it.

## Features

There are quite a few nifty capabilities built right into the packer:

- Targeting specific sections with `--section`
- Doing multiple passes of obfuscation using `--multipass`
- Obfuscating only specific strings using `--stringMatch="string to obfuscate"`
- Obfuscating imports (on by default turned off with `--noImports`)

## Code

The code is written in C++ and the project files are for Visual Studio 2017. There is a dependency on `PeLib`; a version slightly modified to work with the C++17 standard lives in `deps/`.

Because of the usage of some C++17 features, this project and it's dependencies won't cleanly backport to earlier Visual Studio versions.

## Usage

Usage is fully described by running `reloc.exe` with no arguments. Here are some example invocations:

### Standard
```
reloc.exe malware.exe obfuscated_malware.exe
```

### Standard Multipass
```
reloc.exe --multipass malware.exe obfuscated_malware.exe
```

### Standard Win10
```
reloc.exe --win10 malware.exe obfuscated_malware.exe
```

### Obfuscate Strings
```
reloc.exe --stringMatch="hello world" malware.exe obfuscated_malware.exe
```