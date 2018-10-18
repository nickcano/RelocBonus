#include "PeRecompiler.h"
#include <Windows.h>

#include <map>
#include <vector>
#include <string>


/*
	useful refs
	http://reverseengineerlog.blogspot.com/2017/03/activating-windows-loader-debug-messages.html
	https://msdn.microsoft.com/en-us/library/ms809762.aspx
	http://images2015.cnblogs.com/blog/268182/201509/268182-20150906154155451-80554465.jpg (i'm gonna print this for my wall)
*/

// BUG: sometimes windows 10 won't map at 0x10000 at all, causing the preselection loop to go forever;
//      need to update code to use a base address which it knows will get hit
// BUG: for some reason binary won't run unless we rewrite at least 1 section, probably a bug in building
// BUG: sometimes multipass has issues, need to figure out what causes them
// IMPROVEMENT: need to add "dodging" so obfuscation can work 'around' certain data/structures which are
//              needed by loader before relocations without sacrificing obfuscation of an entire section

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
"Usage: reloc.exe [--section=<name> | --multipass | --win10 | --noImports | --rewriteHeader | --stringMatch=<text>] input.exe output.exe\n" \
"    --section=<name>       Rewrite section with <name>\n" \
"    --win10                Use runtime ASLR Preselection attack, required for targets running Windows 10\n" \
"    --noImports            Don't rewrite import names or pointers\n" \
"    --multipass            Go over data multiple times with an offset; this increases obfuscation potency and output size\n" \
"    --rewriteHeader        Rewrite entrypoint; incompatible with --win10 and header must be writable\n" \
"    --fixupBase            Relocate ImageBase in PE header to match actual base; header must be writeable\n" \
"    --stringMatch=<text>   Relocate all occurrences of the string <text>; disables obfuscation of whole sections\n" \
"\n" \
"Notes:\n" \
"    - If no sections are specified, .text, .data, and .rsrc will be used\n" \
"    - Using --win10 will remove .rsrc from the default section list, as win10 doesn't like obfuscated resources\n" \
"    - Using --win10 will set --noImports, as the attack is incompatible with import obfuscation\n" \
"    - Options which say \"header must be writeable\" are effectively useless in the real world, but exist for debugging/experimentation purposes.\n"\
"\n"\
"Example 1 - Standard:\n" \
"    reloc.exe malware.exe obfuscated_malware.exe\n" \
"Example 2 - Standard Win10:\n" \
"    reloc.exe --win10 malware.exe obfuscated_malware.exe\n" \
"Example 3 - Custom Sections:\n" \
"    reloc.exe --section=CODE --section=DATA --section=BSS malware.exe obfuscated_malware.exe\n" \
"Example 4 - Obfuscate Strings:\n" \
"    reloc.exe --stringMatch=\"hello world\" malware.exe obfuscated_malware.exe\n" \
"Example 5 - Obfuscate Strings (Multi-Pass):\n" \
"    reloc.exe --multipass --stringMatch=\"hello world\" malware.exe obfuscated_malware.exe\n" \
"\n" \
"If the output executable crashes or fails to start:\n" \
"    - Obfuscating .rdata can cause issues with certain parts of the PE which may be needed pre-reloc\n" \
"    - Obfuscating .rsrc can sometimes cause issues, still trying to figure out why\n" \
"    - Obfuscating a binary where .reloc isn't the final section will cause section overlap, this needs to be fixed\n" \
"If none of these fix the error, you may be seeing a new bug.\n";

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
	auto multi = (cl.find("--multipass") != cl.end());

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
		compiler.doMultiPass(multi);

		/* load everything up */
		if (!compiler.loadInputFile()) break;
		if (!compiler.loadInputSections()) break;

		/* statically relocate the file to prepare for rewriting */
		if (!compiler.performOnDiskRelocations()) break;

		/* if headr is writeable, we can re-write parts of the header (such as EntryPoint) */
		if (rewriteHeader) if (!compiler.rewriteHeader()) break;

		/* if header is writeable, we can make BaseAddress look normal in memory */
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

