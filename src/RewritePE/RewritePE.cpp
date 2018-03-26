
#include "PeRecompiler.h"
#include <Windows.h>


/*k refs
	http://reverseengineerlog.blogspot.com/2017/03/activating-windows-loader-debug-messages.html
	https://msdn.microsoft.com/en-us/library/ms809762.aspx
	http://images2015.cnblogs.com/blog/268182/201509/268182-20150906154155451-80554465.jpg (i'm gonna print this for my wall)

*/

int main(int argc, char* argv[])
{
	//system("pause");

	std::string input = "test.exe";
	std::string output = "test.rebased.exe";

	if (argc >= 2)
		input = argv[1];
	if (argc >= 3)
		output = argv[2];

	PeRecompiler compiler(std::cout, std::cerr, input, output);

	do
	{
		/* load everything up */
		if (!compiler.loadInputFile()) break;
		if (!compiler.loadInputSections()) break;

		/* statically relocate the file to prepare for rewriting */
		if (!compiler.performOnDiskRelocations()) break;

		/* if the target machine doesn't enforce DEP, we can re-write parts of the header (such as EntryPoint) */
		if (false) if (!compiler.rewriteHeader()) break;

		/* rewrite some sections */
		if (!compiler.rewriteSection(".text")) break;
		if (!compiler.rewriteSection(".data")) break;
		if (!compiler.rewriteSection(".rsrc")) break;

		/* rewrite import tables */
		if (!compiler.rewriteImports()) break;

		/* write out the new binary */
		if (!compiler.writeOutputFile()) break;

		std::cout << "Packing succeeded!" << std::endl;
		return 0;
	} while(0);
	
	std::cout << "Packing failed!" << std::endl;
	return 1;
}

