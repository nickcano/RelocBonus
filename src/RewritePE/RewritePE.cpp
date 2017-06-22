#include "PeLibInclude.h" // this needs to always come before Windows.h or compile error occurs

#include "VectorUtils.h"
#include "RewriteBlock.h"

#include <Windows.h>

#include <memory>

/* refs
	https://msdn.microsoft.com/en-us/library/ms809762.aspx
	http://images2015.cnblogs.com/blog/268182/201509/268182-20150906154155451-80554465.jpg (i'm gonna print this for my wall)

*/


struct PackedBlock // defines a block that has been rewritten
{
	PackedBlock(unsigned int _beginRVA) : beginRVA(_beginRVA), offsets() {}

	unsigned int beginRVA;
	std::vector<unsigned short> offsets;
};



void rebaseExecutable()
{
	bool targetDEPEnabled = true;

	std::string modName = "test.exe";
	std::string newName = "test.rebased.exe";

	/* initial PE load */
	PeLib::PeFile32 peFile = PeLib::PeFile32(modName);

	if (peFile.readMzHeader() != NO_ERROR)
	{
		std::cerr << "Failed to read MzHeader!" << std::endl;
		return;
	}

	if (peFile.readPeHeader() != NO_ERROR)
	{
		std::cerr << "Failed to read PeHeader!" << std::endl;
		return;
	}

	/* some defs for clarity */
	auto& mzHeader = peFile.mzHeader();
	auto& peHeader = peFile.peHeader();


	/* print some useful details and store in vars */
	unsigned int characteristics = peHeader.getDllCharacteristics();
	std::cout << "Characteristics: 0x" << std::hex << characteristics << std::endl;

	unsigned int requestedBase = peHeader.getImageBase();
	std::cout << "Requested Base: 0x" << std::hex << requestedBase << std::endl;

	unsigned int rvaOfReloc = peHeader.getIddBaseRelocRva();
	unsigned int sizeOfReloc = peHeader.getIddBaseRelocSize();
	std::cout << "Reloc RVA: 0x" << std::hex << rvaOfReloc << std::endl;
	std::cout << "Reloc Size: 0x" << std::hex << sizeOfReloc << std::endl;

	/* some checks */
	if ((characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	{
		std::cerr << "Binary must be compiled with ASLR enabled!" << std::endl;
		return;
	}

	/* turn off ASLR (needed for next step) and DEP (needed to overwrite certain parts of header) */
	characteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	if (!targetDEPEnabled) characteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	peHeader.setDllCharacteristics(characteristics);

	/* request a base address of 0xFFFF0000 (which causes us to load at 0x00010000 on w7) */
	peHeader.setImageBase(0xFFFF0000);

	/* read all section contents into buffers so so we can apply relocs */
	std::ifstream file(modName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
	if (!file.is_open())
	{
		std::cerr << "Failed to read original file!" << std::endl;
		return;
	}

	std::vector<std::shared_ptr<PeSectionContents>> sectionContents;
	for (unsigned int sec = 0; sec < peFile.peHeader().getNumberOfSections(); sec++)
	{
		auto sc = std::make_shared<PeSectionContents>();
		sc->index = sec;
		sc->RVA = peHeader.getVirtualAddress(sec);
		sc->size = peHeader.getSizeOfRawData(sec);
		sc->rawPointer = peHeader.getPointerToRawData(sec);
		sc->virtualSize = peHeader.getVirtualSize(sec);
		sc->name = peHeader.getSectionName(sec);

		char* block = new char[sc->size];
		file.seekg(peHeader.getPointerToRawData(sec), std::ios::beg);
		file.read(block, sc->size);

		sc->data = std::vector<PeLib::byte>(block, block + sc->size);
		sectionContents.push_back(sc);

		delete [] block;
	}

	file.close();


	/* store the blocks that we will rewrite (encrypt) */
	std::vector<std::shared_ptr<RewriteBlock>> rewriteBlocks;

	/* rewrite entry point if no DEP */
	if (!targetDEPEnabled) // encrypt entry point (only possible when DEP is off)
		rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new EntryPointRewriteBlock(&peFile)));

	/* rewrite basic sections */
	for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++) // encrypt sections
	{
		auto& sec = *isec;
		if (sec->name.compare(".text") == 0 ||
			sec->name.compare(".data") == 0)
			rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(sec)));
	}

	/* some rewrite helpers (TODO: move to funcs) */
	auto getSectionByRVA = [&sectionContents](unsigned int RVA, unsigned int size) -> std::shared_ptr<PeSectionContents>
	{
		if (!RVA || !size)
			return nullptr;

		for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++)
		{
			auto& sec = *isec;
			if (RVA < sec->RVA || RVA >= (sec->RVA + sec->size) || (RVA + size) > (sec->RVA + sec->size))
				continue;
			return sec;
		}
		return nullptr;
	};

	auto rewriteSubsectionByRVA = [getSectionByRVA, &sectionContents](unsigned int RVA, unsigned int size) -> std::shared_ptr<RewriteBlock>
	{
		auto sec = getSectionByRVA(RVA, size);
		if (!sec)
			return nullptr;
		return std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(sec, RVA - sec->RVA, size));
	};

	/* rewrite Import Address Table */
	unsigned int iatRVA = peHeader.getIddIatRva();
	unsigned int iatSize = peHeader.getIddIatSize();
	rewriteBlocks.push_back(rewriteSubsectionByRVA(iatRVA, iatSize));

	/* rewrite Import Directory Table */
	unsigned importRVA = peHeader.getIddImportRva();
	unsigned importSize = peHeader.getIddImportSize();
	rewriteBlocks.push_back(rewriteSubsectionByRVA(importRVA, importSize));

	/* rewrite Import Hints/Names & Dll Names Table */
	auto iatSec = getSectionByRVA(iatRVA, iatSize);
	if (iatSec)
	{
		unsigned int iatOffset = iatRVA - iatSec->RVA;

		unsigned int lowestNameRVA = 0xFFFFFFFF;
		unsigned int highestNameRVA = 0;
		for (unsigned int imp = iatOffset; imp < iatOffset + iatSize; imp += 4)
		{
			unsigned int temp;
			if (!getData(iatSec->data, imp, temp))
				break;
			if (temp == 0) continue;
			else if (temp < lowestNameRVA) lowestNameRVA = temp;
			else if (temp > highestNameRVA) highestNameRVA = temp;
		}

		rewriteBlocks.push_back(rewriteSubsectionByRVA(lowestNameRVA, highestNameRVA - lowestNameRVA));
	}

	/*
		do all of the relocs within the binary itself.
		because we are requesting a base address different than what we're compiled for,
		and because we wont even get the one we request, this cannot be done by the loader.
	*/
	if (peFile.readRelocationsDirectory())
	{
		std::cerr << "Failed to read reloc directory!" << std::endl;
		return;
	}

	int relocDelta = 0x10000 - requestedBase;

	auto& reloc = peFile.relocDir();
	for (unsigned int rel = 0; rel < reloc.calcNumberOfRelocations(); rel++)
	{
		unsigned int relocBlockRVA = reloc.getVirtualAddress(rel);
		unsigned int relocBlockSize = reloc.getSizeOfBlock(rel);
		unsigned int relocBlockCount = reloc.calcNumberOfRelocationData(rel);

		std::shared_ptr<PeSectionContents> sc = nullptr;
		for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++)
		{
			auto& sec = *isec;
			if (relocBlockRVA < sec->RVA || relocBlockRVA >= (sec->RVA + sec->size))
				continue;
			sc = sec;
			break;
		}

		if (!sc)
		{
			std::cerr << "Reloc has no matching section!" << std::endl;
			return;
		}


		for (unsigned int relEntry = 0; relEntry < relocBlockCount; relEntry++)
		{
			unsigned short entry = reloc.getRelocationData(rel, relEntry);
			unsigned short entryType = (entry >> 12);
			unsigned int entryAddress = relocBlockRVA + (entry & 0x0FFF);

			unsigned int si = entryAddress - sc->RVA;
			if (entryType & IMAGE_REL_BASED_HIGHLOW)
			{
				unsigned int original;
				if (!getData(sc->data, si, original))
				{
					std::cerr << "Failed to read original value to reloc!" << std::endl;
					return;
				}
				putData(sc->data, si, original + relocDelta);
			}
			else if (entryType)
			{
				std::cerr << "Unknown entry type! " << entryType << std::endl;
			}
		}
	}

	/* pack blocks */
	unsigned int packDelta = (0x10000 - 0xFFFF0000);
	const unsigned int dataSize = 4;
	const unsigned int chunkSize = 1024 * dataSize;
	std::vector<PackedBlock> packedBlocks;

	for (auto iblock = rewriteBlocks.begin(); iblock != rewriteBlocks.end(); iblock++)
	{
		auto& block = *iblock;
		if (!block)
			continue;

		unsigned int rva, offset;
		if (!block->getFirstEntryLoc(dataSize, rva, offset))
			continue;
		packedBlocks.push_back(PackedBlock(rva));

		do
		{
			if (!block->decrementEntry(offset, packDelta))
				break;

			auto packedBlock = &packedBlocks[packedBlocks.size() - 1];
			auto rvaOffset = static_cast<unsigned short>((rva - packedBlock->beginRVA));
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

	/* clear relocations */
	while (reloc.calcNumberOfRelocations())
		reloc.removeRelocation(0);

	/* fill new reloc table */
	for (auto ipb = packedBlocks.begin(); ipb != packedBlocks.end(); ipb++)
	{
		auto& packedBlock = *ipb;

		unsigned int rel = reloc.calcNumberOfRelocations();
		reloc.addRelocation();

		for (auto offset = packedBlock.offsets.begin(); offset != packedBlock.offsets.end(); offset++)
			reloc.addRelocationData(rel, (IMAGE_REL_BASED_HIGHLOW << 12) | (*offset & 0x0FFF));

		unsigned int relocSize = (packedBlock.offsets.size() * sizeof(unsigned short)) + 8; // + 8 for the header size
		if (packedBlock.offsets.size() % 2 == 1) // each reloc entry set should be aligned on 4 byte boundary
		{
			reloc.addRelocationData(rel, 0);
			relocSize += sizeof(unsigned short);
		}

		// update the header
		reloc.setVirtualAddress(rel, packedBlock.beginRVA);
		reloc.setSizeOfBlock(rel, relocSize);
	}

	/* update section metadata & contents for relocs */
	bool updatedRelocs = false;
	for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++)
	{
		auto& sec = *isec;
		if (sec->RVA != rvaOfReloc)
			continue;

		sec->data.clear();
		reloc.rebuild(sec->data);
		peHeader.setVirtualSize(sec->index, sec->data.size());
		peHeader.setIddBaseRelocSize(sec->data.size());

		while (sec->data.size() % 512) // size of raw data should be aligned on 512 boundary for FS mapping
			sec->data.push_back(0x00);
		peHeader.setSizeOfRawData(sec->index, sec->data.size());

		updatedRelocs = true;
		break;
	}

	if (!updatedRelocs)
	{
		std::cerr << "Failed to locate reloc section!" << std::endl;
		return;
	}

	/* validate the binary since we changed some section stuff */
	peFile.peHeader().makeValid(peFile.mzHeader().getAddressOfPeHeader());
	
	/* write original MZ and PE headers to new binary */
	mzHeader.write(newName, 0);
    peHeader.write(newName, peFile.mzHeader().getAddressOfPeHeader());
        
	/* write original section meta-data to new binary */
    peHeader.writeSections(newName);

	/* write all section contents out to new file */
	for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++)
	{
		auto& sec = *isec;
		if (sec->size)
			peHeader.writeSectionData(newName, sec->index, sec->data);
	}
}

int main(int argc, char* argv[])
{
	system("pause");
	rebaseExecutable();

	return 0;
}

