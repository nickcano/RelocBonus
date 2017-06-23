#pragma once
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <stdint.h>

class RewriteBlock;
namespace PeLib { class PeFile32; };

struct PeSectionContents
{
	std::string name;
	std::vector<uint8_t> data;
	uint32_t index, RVA, size, virtualSize, rawPointer;
};

class PeRecompiler
{
public:
	PeRecompiler(
		std::ostream &_infoStream, std::ostream &_errorStream,
		const std::string &_inputFileName, const std::string &_outputFileName
	);
	~PeRecompiler() {}

	bool loadInputFile();
	bool loadInputSections();

	bool performOnDiskRelocations();

	bool rewriteHeader();
	bool rewriteSection(const std::string &name);
	bool rewriteImports();

	bool writeOutputFile();

private:
	std::ostream &infoStream, &errorStream;
	std::string inputFileName, outputFileName;
	std::shared_ptr<PeLib::PeFile32> peFile;

	std::vector<std::shared_ptr<PeSectionContents>> sectionContents;
	std::vector<std::shared_ptr<RewriteBlock>> rewriteBlocks;

	bool doRewriteReadyCheck();
	std::shared_ptr<PeSectionContents> getSectionByRVA(uint32_t RVA, uint32_t size);
	bool rewriteSubsectionByRVA(uint32_t RVA, uint32_t size);
};