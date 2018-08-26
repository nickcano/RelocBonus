
#include "PeRecompiler.h"
#include <Windows.h>

#include <map>
#include <vector>
#include <string>


/*refs
	http://reverseengineerlog.blogspot.com/2017/03/activating-windows-loader-debug-messages.html
	https://msdn.microsoft.com/en-us/library/ms809762.aspx
	http://images2015.cnblogs.com/blog/268182/201509/268182-20150906154155451-80554465.jpg (i'm gonna print this for my wall)
*/

/* windows 10 workarounds
	This doesn't work out of the box on Windows 10, so there are a few workarounds.

	Method 1 - Execution Options
		Method:
			Setting "Image File Execution Options" option "Mandatory ASLR" to "On" and "Bottom-Up ASLR" to "Off" causes it to work.
			Reg keys:
				Name: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\name_of_exe\MitigationAuditOptions
				Type: REG_BINARY
				Value: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

				Name: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\name_of_exe\MitigationOptions
				Type: REG_BINARY
				Value: 00 01 22 00 00 00 00 00 00 00 00 00 00 00 00 00 
		Drawbacks:
			- Requires admin
			- Easy to monitor these keys
			- Requires execution before the packed code
	Method 2 - ASLR Preselection
		Method:
			Step 1: Generate packed binary expecting a base address which is valid with "Bottom-Up ASLR" (something like 0x03B00000) instead of the expected 0x00010000
			Step 2: Some pre-launcher spams LoadLibrary on the executable, watching for the expected base address to appear.
			step 2b: after a LoadLibrary call which doesn't give the proper base, call FreeLibrary and then use VirtualAlloc to occupy that memory, forcing the next allocation to a new address.
			Step 3: Once the expected base appears, launch the binary. Loader should re-use this base.
		Drawbacks:
			- Slim but real possibility that the chosen base will conflict with another that is in-use
			- Requires execution before the packed code
			- May not be compatible with systems which are vulnerable to the original attack
	Method 3 - Hybrid
		Method:
			Method 1 causes the system to behave like Windows 7 and allows the original attack to work.
			Method 2 is an attack tailored to systems on which it doesn't work, and which may not work on older systems.
			Method 3 will take both of these into account. When packing the PE header, it will generate a duplicate of each PE section.
				The orignal sections will be tailored to the original attack. It will work on W7 and, on the off-chance the W10 settings are right, it will work there as well.
				The duplicates of the sections will be created as if they are carrying out the Method 2 attack.
			Method 3 will then inject a small stub of position-agnostic code which can act as the pre-loader.
				This code will check if the base is 0x00010000, and jump to the original entry-point if so.
				Next, if this code magically happens to fall at the preselected bottom-up base (unlikely), it will jump to the duplicate entry-point.
				Otherwise, this code will make a copy of the binary and begin running the ASLR preselection attack with the copied binary, executing it upon success.
			Optionally, we can N-plicate instead of duplicate and preselect N addresses, since there's a small chance preselection can fail when an address in in-use.
		Drawbacks:
			- Doubles the size of the binary because of section duplicates
			- Copying of self executable may be seen as suspicious



	############ OKAY SO THE ABOVE KINDA WRONG ############
		The mentions about ASLR Preselection aren't exactly accurate.
		#1 we don't need to use a different address for preselection, 0x10000 will work
		#2 The LoadLibrary/VirtualAlloc/FreeLibrary method doesn't work as originally thought.
			The right way is to have the first instance make a copy of itself, then launch that copy in a loop until it has the right base address.
			Grabbing and closing a mapping to the copy between executions will force a new base address every time.
			The copy should have a way to tell the original if it failed or succeeded, success meaning it sees 0x10000 ad it's own base address.

*/


// BUG: if reloc isn't the final section, corrupts pe
// BUG: for some reason binary won't run unless we rewrite at least 1 section, probably a bug in building
// TODO FOR PRES: add debugging stuff

bool startsWith(const std::string& s, const std::string& prefix)
{
	return (s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0);
}

auto split(const std::string& s, char delim, size_t max=-1)
{
	auto start = 0;
	std::vector<std::string> res;
	while (start != std::string::npos && (max == -1 || res.size() < (max - 1)))
	{
		auto pos = s.find(delim);
		auto sub = (pos == std::string::npos) ? s.substr(start) : s.substr(start, pos - start);
		res.push_back(sub);
		start = (pos == std::string::npos) ? pos : ++pos;
	}
	if (start != std::string::npos)
		res.push_back(s.substr(start));
	return res;
}

typedef std::map<std::string, std::vector<std::string>> CommandLine;
auto parseCommandLine(int argc, char* argv[])
{
	std::vector<std::string> args;
	for (int i = 0; i < argc; i++)
		args.push_back(argv[i]);

	CommandLine cl;
	for (auto arg : args)
	{
		auto isSwitch = startsWith(arg, "--");
		if (isSwitch)
		{
			auto parts = split(arg, '=', 2);
			auto key = (parts.size() == 2) ? parts[0] : arg;
			cl[key] = cl[key]; // trick to automatically new() upon first discovery
			if (parts.size() == 2)
				cl[key].push_back(parts[1]);
		}
		else
			cl[""].push_back(arg);
	}
	
	return cl;
}

const char* usageString =
"Usage: reloc.exe [--section=<name> | --win10 | --noImports | --rewriteHeader | --stringMatch=<text>] input.exe output.exe\n" \
"    --section=<name>       Rewrite section with <name>\n" \
"    --win10                Use runtime ASLR Preselection attack, required for targets running Windows 10\n" \
"    --noImports            Don't rewrite import names or pointers\n" \
"    --rewriteHeader        Rewrite entrypoint; incompatible with --win10 and header must be writable\n" \
"    --fixupBase            Relocate ImageBase in PE header to match actual base; header must be writeable\n" \
"    --stringMatch=<text>   Relocate all occurrences of the string <text>; disables obfuscation of whole sections\n" \
"\n" \
"Notes:\n" \
"    - If no sections are specified, .text, .data, and .rsrc will be used\n" \
"    - Using --win10 will remove .rsrc from the default section list, as win10 doesn't like obfuscated resources\n" \
"    - Using --win10 will set --noImports, as the attack is incompatible with import obfuscation\n" \
"    - Options which say \"header must be writeable\" are effectively useless in the real world, but exist for debugging/experimentation purposes. "\
"\n"\
"Example 1 - Standard:\n" \
"    reloc.exe malware.exe obfuscated_malware.exe\n" \
"Example 2 - Standard Win10:\n" \
"    reloc.exe --win10 malware.exe obfuscated_malware.exe\n" \
"Example 3 - Custom Sections:\n" \
"    reloc.exe --section=CODE --section=DATA --section=BSS malware.exe obfuscated_malware.exe\n" \
"Example 4 - Obfuscate Strings:\n" \
"    reloc.exe --stringMatch=\"hello world\" malware.exe obfuscated_malware.exe\n";

int main(int argc, char* argv[])
{
	auto cl = parseCommandLine(argc, argv);

	auto args = cl[""];
	if (args.size() != 3)
	{
		std::cout << usageString << std::endl;
		return ERROR_INVALID_PARAMETER;
	}

	auto win10 = (cl.find("--win10") != cl.end());
	auto noImports = (cl.find("--noImports") != cl.end()) || win10;
	auto rewriteHeader = (cl.find("--rewriteHeader") != cl.end());
	auto fixupBase = (cl.find("--fixupBase") != cl.end());

	auto sections = cl["--section"];
	auto stringMatchList = cl["--stringMatch"];

	if (!stringMatchList.size())
	{
		if (sections.size() == 0)
		{
			sections.push_back(".text");
			sections.push_back(".data");
			if (!win10)
				sections.push_back(".rsrc");
		}
	}
	else if (sections.size())
	{
		std::cout << "Disabling obfuscation of whole sections due to --stringMatch" << std::endl;
		sections.clear();
	}

	PeRecompiler compiler(std::cout, std::cerr, args[1], args[2]);
	do
	{
		compiler.useWindows10Attack(win10);

		/* load everything up */
		if (!compiler.loadInputFile()) break;
		if (!compiler.loadInputSections()) break;

		/* statically relocate the file to prepare for rewriting */
		if (!compiler.performOnDiskRelocations()) break;

		/* if the target machine doesn't enforce DEP, we can re-write parts of the header (such as EntryPoint) */
		if (rewriteHeader) if (!compiler.rewriteHeader()) break;

		/* if the target machine doesn't enforce DEP, we can make BaseAddress look normal in memory */
		if (fixupBase) if (!compiler.fixupBase()) break;

		/* rewrite some sections */
		if (sections.size())
			std::cout << "Obfuscating sections" << std::endl;
		bool failed = false;
		for (auto sec : sections)
		{
			if (!compiler.rewriteSection(sec))
			{
				failed = true;
				break;
			}
		}
		if (failed) break;

		/* rewrite string matches */
		if (stringMatchList.size())
			std::cout << "Obfuscating string matches" << std::endl;
		failed = false;
		for (auto str : stringMatchList)
		{
			if (!compiler.rewriteMatches(str))
			{
				failed = true;
				break;
			}
		}
		if (failed) break;

		/* rewrite import tables */
		if (!noImports) if (!compiler.rewriteImports()) break;

		/* write out the new binary */
		if (!compiler.writeOutputFile()) break;

		std::cout << "Packing succeeded!" << std::endl;
		return 0;
	} while(0);
	
	std::cout << "Packing failed!" << std::endl;
	return 1;
}

