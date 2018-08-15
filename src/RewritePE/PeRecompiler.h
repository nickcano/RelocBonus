#pragma once
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <stdint.h>

class RewriteBlock;
namespace PeLib { class PeFile32; };

class PeSectionContents
{
public:
	std::string name;
	std::vector<uint8_t> data;
	uint32_t index, RVA, size, virtualSize, rawPointer;

	PeSectionContents() {}
	PeSectionContents(uint32_t index, std::shared_ptr<PeLib::PeFile32> &_header, std::ifstream &file);

	void print(std::ostream &stream);
};

class PeRecompiler
{
public:
	PeRecompiler(
		std::ostream &_infoStream, std::ostream &_errorStream,
		const std::string &_inputFileName, const std::string &_outputFileName
	);
	~PeRecompiler() {}

	void useWindows10Attack(bool win10);

	bool loadInputFile();
	bool loadInputSections();

	bool performOnDiskRelocations();

	bool rewriteHeader();
	bool fixupBase();
	bool rewriteSection(const std::string &name);
	bool rewriteImports();

	bool writeOutputFile();

private:
	bool shouldUseWin10Attack;
	std::ostream &infoStream, &errorStream;
	std::string inputFileName, outputFileName;
	std::shared_ptr<PeLib::PeFile32> peFile;

	std::vector<std::shared_ptr<PeSectionContents>> sectionContents;
	std::vector<std::shared_ptr<RewriteBlock>> rewriteBlocks;

	bool doRewriteReadyCheck();
	std::shared_ptr<PeSectionContents> getSectionByRVA(uint32_t RVA, uint32_t size);
	bool rewriteSubsectionByRVA(uint32_t RVA, uint32_t size);
};