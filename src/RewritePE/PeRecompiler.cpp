#include "PeLibInclude.h" 

#include "PeRecompiler.h"
#include "VectorUtils.h"
#include "RewriteBlock.h"

#include <Windows.h>


const uint32_t TRICKY_BASE_ADDRESS = 0xFFFF0000;
const uint32_t ACTUALIZED_BASE_ADDRESS = 0x00010000;


PeRecompiler::PeRecompiler(
	std::ostream &_infoStream, std::ostream &_errorStream,
	const std::string &_inputFileName, const std::string &_outputFileName
)
	: infoStream(_infoStream), errorStream(_errorStream),
	inputFileName(_inputFileName), outputFileName(_outputFileName)
{
	this->infoStream << std::hex;
	this->errorStream << std::hex;
}


bool PeRecompiler::loadInputFile()
{
	auto peFile = std::make_shared<PeLib::PeFile32>(this->inputFileName);
	if (peFile->readMzHeader() != NO_ERROR)
	{
		this->errorStream << "Failed to read MzHeader: " << this->inputFileName << std::endl;
		return false;
	}

	if (peFile->readPeHeader() != NO_ERROR)
	{
		this->errorStream << "Failed to read PeHeader: " << this->inputFileName << std::endl;
		return false;
	}

	this->peFile = peFile;
	this->infoStream << "Successfully loaded PE File: " << this->inputFileName << std::endl;
	return true;
}

bool PeRecompiler::loadInputSections()
{
	if (!this->peFile)
		return false;

	std::ifstream file(this->inputFileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
	if (!file.is_open())
	{
		this->errorStream << "Failed to open original file for section reading: " << this->inputFileName << std::endl;
		return false;
	}

	auto& peHeader = this->peFile->peHeader();
	for (unsigned int sec = 0; sec < peHeader.getNumberOfSections(); sec++)
	{
		auto sc = std::make_shared<PeSectionContents>();
		sc->index = sec;
		sc->RVA = peHeader.getVirtualAddress(sec);
		sc->size = peHeader.getSizeOfRawData(sec);
		sc->rawPointer = peHeader.getPointerToRawData(sec);
		sc->virtualSize = peHeader.getVirtualSize(sec);
		sc->name = peHeader.getSectionName(sec);

		this->infoStream << "Loading section " << sc->name << std::endl;
		this->infoStream << "\tVirtual Size: 0x" << sc->virtualSize << std::endl;
		this->infoStream << "\tRVA: 0x" << sc->RVA << std::endl;
		this->infoStream << "\tRaw Size: 0x" << sc->size << std::endl;
		this->infoStream << "\tRaw Pointer: 0x" << sc->rawPointer << std::endl;

		char* block = new char[sc->size];
		file.seekg(peHeader.getPointerToRawData(sec), std::ios::beg);
		file.read(block, sc->size);

		sc->data = std::vector<uint8_t>(block, block + sc->size);
		this->sectionContents.push_back(sc);

		delete [] block;
	}

	file.close();

	return true;
}

bool PeRecompiler::performOnDiskRelocations()
{
	if (!this->peFile)
		return false;

	/* first, make sure everything is as it must be */
	if (!this->sectionContents.size())
	{
		this->errorStream << "Section contents must be loaded before doing any relocations!" << std::endl;
		return false;
	}

	auto& peHeader = this->peFile->peHeader();

	uint32_t characteristics = peHeader.getDllCharacteristics();
	uint32_t requestedBase = peHeader.getImageBase();

	if ((characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	{
		this->errorStream << "Binary must have ASLR enabled to perform on-disk relocations!" << std::endl;
		return false;
	}

	if (this->peFile->readRelocationsDirectory())
	{
		this->errorStream << "Failed to read reloc directory!" << std::endl;
		return false;
	}

	/*
		now, our first step is to remove the ASLR flag and request a base of TRICKY_BASE_ADDRESS.
		this actually causes us to load at ACTUALIZED_BASE_ADDRESS, though, so we will relocate to there.
	*/
	auto newCharacteristics = (characteristics & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	peHeader.setDllCharacteristics(newCharacteristics);
	this->infoStream << "Stripped IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag" << std::endl;
	this->infoStream << "\tOld Characteristics: 0x" << characteristics << std::endl;
	this->infoStream << "\tNew Characteristics: 0x" << newCharacteristics << std::endl;

	peHeader.setImageBase(TRICKY_BASE_ADDRESS);
	this->infoStream << "Changed ImageBase to 0x" << TRICKY_BASE_ADDRESS << " (was 0x" << requestedBase << ")" << std::endl;


	/* now let's relocate everything to 0x10000 */
	uint32_t numberOfRelocsPerformed = 0;
	auto& reloc = this->peFile->relocDir();
	const int32_t relocDelta = ACTUALIZED_BASE_ADDRESS - requestedBase;
	for (unsigned int rel = 0; rel < reloc.calcNumberOfRelocations(); rel++)
	{
		uint32_t relocBlockRVA = reloc.getVirtualAddress(rel);
		uint32_t relocBlockSize = reloc.getSizeOfBlock(rel);
		auto sc = this->getSectionByRVA(relocBlockRVA, 4);
		if (!sc)
		{
			this->errorStream << "Reloc has no matching section! RVA: 0x" << relocBlockRVA << std::endl;
			return false;
		}

		auto relocBlockCount = reloc.calcNumberOfRelocationData(rel);
		for (unsigned int relEntry = 0; relEntry < relocBlockCount; relEntry++)
		{
			uint16_t entry = reloc.getRelocationData(rel, relEntry);
			uint16_t entryType = (entry >> 12);
			uint32_t entryAddress = relocBlockRVA + (entry & 0x0FFF);

			uint32_t si = entryAddress - sc->RVA;
			if (entryType & IMAGE_REL_BASED_HIGHLOW)
			{
				uint32_t original;
				if (!getData(sc->data, si, original))
				{
					this->errorStream << "Failed to read original value to reloc!" << std::endl;
					return false;
				}
				putData(sc->data, si, original + relocDelta);
			}
			else if (entryType)
			{
				this->errorStream << "Unknown reloc type: 0x" << entryType << std::endl;
				return false;
			}

			numberOfRelocsPerformed++;
		}
	}

	this->infoStream << "Parsed original reloc table and applied " << std::dec << numberOfRelocsPerformed << std::hex << " relocations" << std::endl;
	this->infoStream << "\tDelta of 0x" << relocDelta << " applied, as binary will load at 0x" << ACTUALIZED_BASE_ADDRESS << std::endl;

	/* we also need to clear out the original reloc table */
	while (reloc.calcNumberOfRelocations())
		reloc.removeRelocation(0);

	this->infoStream << "Cleared original reloc table" << std::endl;

	return true;
}

bool PeRecompiler::rewriteHeader()
{
	if (!this->doRewriteReadyCheck())
		return false;
	this->rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new EntryPointRewriteBlock(this->peFile)));
	this->infoStream << "Rewrote header entrypoint" << std::endl;
	return true;
}

bool PeRecompiler::rewriteSection(const std::string &name)
{
	if (!this->doRewriteReadyCheck())
		return false;

	for (auto isec = this->sectionContents.begin(); isec != this->sectionContents.end(); isec++)
	{
		auto& sec = *isec;
		if (sec->name.compare(name) == 0)
		{
			this->rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(sec)));
			this->infoStream << "Rewrote " << name << " section at RVA: 0x" << sec->RVA << std::endl;
			return true;
		}
	}

	this->infoStream << "Seemingly no section named " << name << " to rewrite" << std::endl;
	return true;
}

bool PeRecompiler::rewriteImports()
{
	if (!this->doRewriteReadyCheck())
		return false;

	auto& peHeader = this->peFile->peHeader();

	/* rewrite Import Address Table */
	uint32_t iatRVA = peHeader.getIddIatRva();
	uint32_t iatSize = peHeader.getIddIatSize();
	if (!this->rewriteSubsectionByRVA(iatRVA, iatSize))
		this->infoStream << "Seemingly no Import Address Table to rewrite" << std::endl;
	else
		this->infoStream << "Rewrote Import Address Table from RVA 0x" << iatRVA << " to 0x" << (iatRVA + iatSize) << std::endl;

	/* rewrite Import Directory Table */
	uint32_t importRVA = peHeader.getIddImportRva();
	uint32_t importSize = peHeader.getIddImportSize();
	if (!this->rewriteSubsectionByRVA(importRVA, importSize))
		this->infoStream << "Seemingly no Import Table to rewrite" << std::endl;
	else
		this->infoStream << "Rewrote Import Table from RVA 0x" << importRVA << " to 0x" << (importRVA + importSize) << std::endl;

	/* rewrite Import Hints/Names & Dll Names Table */
	auto iatSec = getSectionByRVA(iatRVA, iatSize);
	if (iatSec)
	{
		uint32_t iatOffset = iatRVA - iatSec->RVA;

		uint32_t lowestNameRVA = 0xFFFFFFFF;
		uint32_t highestNameRVA = 0;
		for (uint32_t imp = iatOffset; imp < iatOffset + iatSize; imp += 4)
		{
			uint32_t temp;
			if (!getData(iatSec->data, imp, temp))
				break;
			if (temp == 0) continue;
			else if (temp < lowestNameRVA) lowestNameRVA = temp;
			else if (temp > highestNameRVA) highestNameRVA = temp;
		}

		if (!this->rewriteSubsectionByRVA(lowestNameRVA, highestNameRVA - lowestNameRVA))
			this->infoStream << "Seemingly no Import Hints/Names & Dll Names Table to rewrite" << std::endl;
		else
			this->infoStream << "Rewrote Import Hints/Names & Dll Names Table from RVA 0x" << lowestNameRVA << " to 0x" << highestNameRVA << std::endl;
	}

	return true;
}

bool PeRecompiler::writeOutputFile()
{
	if (!this->peFile)
		return false;

	if (!this->sectionContents.size())
	{
		this->errorStream << "Section contents must be loaded before writing output!" << std::endl;
		return false;
	}

	auto& reloc = this->peFile->relocDir();
	auto& peHeader = this->peFile->peHeader();
	auto& mzHeader = this->peFile->mzHeader();

	/*
		first, we need to actually DO THE REWRITES that we have queued up.
		we will modify the contents buffers we have in rewriteBlocks and
		keep a ledger of those so we can generate a reloc table later.
	*/
	struct PackedBlock
	{
		PackedBlock(unsigned int _beginRVA) : beginRVA(_beginRVA), offsets() {}
		unsigned int beginRVA;
		std::vector<unsigned short> offsets;
	};
	std::vector<PackedBlock> packedBlocks;

	const uint32_t packDelta = (ACTUALIZED_BASE_ADDRESS - TRICKY_BASE_ADDRESS);
	const uint32_t dataSize = 4;
	const uint32_t chunkSize = 1024 * dataSize;
	for (auto iblock = this->rewriteBlocks.begin(); iblock != this->rewriteBlocks.end(); iblock++)
	{
		auto& block = *iblock;
		if (!block)
			continue;

		uint32_t rva, offset;
		if (!block->getFirstEntryLoc(dataSize, rva, offset))
			continue;
		packedBlocks.push_back(PackedBlock(rva));

		do
		{
			if (!block->decrementEntry(offset, packDelta))
				break;

			auto packedBlock = &packedBlocks[packedBlocks.size() - 1];
			auto rvaOffset = static_cast<uint16_t>((rva - packedBlock->beginRVA));
			if (rvaOffset >= chunkSize)
			{
				rvaOffset = 0;
				packedBlocks.push_back(PackedBlock(rva));
				packedBlock = &packedBlocks[packedBlocks.size() - 1];
			}

			packedBlock->offsets.push_back(rvaOffset);
		}
		while (block->getNextEntryLoc(dataSize, offset, rva, offset));
	}

	/* now that that's done, we actually need to generate a reloc table... */
	if (packedBlocks.size())
	{
		this->infoStream << "Applied all rewrites to actual file contents" << std::endl;

		if (reloc.calcNumberOfRelocations())
		{
			this->errorStream << "No relocation table should exist if rewrites are present!" << std::endl;
			return false;
		}

		/* generate a new reloc entry for each packed block */
		for (auto ipb = packedBlocks.begin(); ipb != packedBlocks.end(); ipb++)
		{
			auto& packedBlock = *ipb;

			unsigned int rel = reloc.calcNumberOfRelocations();
			reloc.addRelocation();

			for (auto offset = packedBlock.offsets.begin(); offset != packedBlock.offsets.end(); offset++)
				reloc.addRelocationData(rel, (IMAGE_REL_BASED_HIGHLOW << 12) | (*offset & 0x0FFF));

			/*
				calculate the header values and write them.
				size needs +8 to include headr itself.
				number of entries should be even to align entire table on 4-byte boundary.
			*/
			uint32_t relocSize = (packedBlock.offsets.size() * sizeof(uint16_t)) + 8;
			if (packedBlock.offsets.size() % 2 == 1)
			{
				reloc.addRelocationData(rel, 0);
				relocSize += sizeof(uint16_t);
			}
			reloc.setVirtualAddress(rel, packedBlock.beginRVA);
			reloc.setSizeOfBlock(rel, relocSize);
		}

		this->infoStream << "Generated reloc table for rewrites with " << std::dec << packedBlocks.size() << std::hex << " entries" << std::endl;
	}


	/*
		embed the new reloc table in place of the old one.
		make sure the raw data is aligned on a 512-byte boundary for filesystem mapping.
	*/
	auto relocSec = this->getSectionByRVA(peHeader.getIddBaseRelocRva(), 4);
	if (!relocSec)
	{
		std::cerr << "Failed to locate reloc section!" << std::endl;
		return false;
	}

	relocSec->data.clear();
	reloc.rebuild(relocSec->data);
	peHeader.setVirtualSize(relocSec->index, relocSec->data.size());
	peHeader.setIddBaseRelocSize(relocSec->data.size());
	while (relocSec->data.size() % 512)
		relocSec->data.push_back(0x00);
	peHeader.setSizeOfRawData(relocSec->index, relocSec->data.size());

	this->infoStream << "Updated PE header with new reloc meta-data" << std::endl;

	/* validate the binary since we changed some sections */
	peHeader.makeValid(mzHeader.getAddressOfPeHeader());

	this->infoStream << "Validated new PE header" << std::endl;
	
	/* write original MZ and PE headers to new binary */
	mzHeader.write(this->outputFileName, 0);
	this->infoStream << "Wrote MZ Header to output file" << std::endl;

    peHeader.write(this->outputFileName, mzHeader.getAddressOfPeHeader());
	this->infoStream << "Wrote PE Header to output file" << std::endl;
        
	/* write section meta-data and contents to new binary */
    peHeader.writeSections(this->outputFileName);
	this->infoStream << "Wrote PE Section meta-data to output file" << std::endl;

	for (auto isec = this->sectionContents.begin(); isec != this->sectionContents.end(); isec++)
	{
		auto& sec = *isec;
		if (sec->size)
			peHeader.writeSectionData(this->outputFileName, sec->index, sec->data);
	}
	this->infoStream << "Wrote PE Section Contents to output file" << std::endl;

	return true;
}


bool PeRecompiler::doRewriteReadyCheck()
{
	if (!this->peFile)
		return false;

	if (!this->sectionContents.size())
	{
		this->errorStream << "Section contents must be loaded before doing rewrites!" << std::endl;
		return false;
	}

	if (this->peFile->relocDir().calcNumberOfRelocations() || this->peFile->peHeader().getImageBase() != TRICKY_BASE_ADDRESS)
	{
		this->errorStream << "On-disk relocations must be performed before doing rewrites!" << std::endl;
		return false;
	}

	return true;
}

std::shared_ptr<PeSectionContents> PeRecompiler::getSectionByRVA(uint32_t RVA, uint32_t size)
{
	if (!RVA || !size)
		return nullptr;

	for (auto isec = this->sectionContents.begin(); isec != this->sectionContents.end(); isec++)
	{
		auto& sec = *isec;
		if (RVA < sec->RVA || RVA >= (sec->RVA + sec->size) || (RVA + size) > (sec->RVA + sec->size))
			continue;
		return sec;
	}
	return nullptr;
}

bool PeRecompiler::rewriteSubsectionByRVA(uint32_t RVA, uint32_t size)
{
	auto sec = getSectionByRVA(RVA, size);
	if (!sec)
		return false;
	this->rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(sec, RVA - sec->RVA, size)));
	return true;
}