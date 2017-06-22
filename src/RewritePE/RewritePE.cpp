#include "PeLibInclude.h" // this needs to always come before Windows.h or compile error occurs

#include <Windows.h>

#include <memory>

struct PeSectionContents
{
	std::string name;
	std::vector<PeLib::byte> data;
	unsigned int index, RVA, size, virtualSize, rawPointer;
};

struct PackedChunk
{
	bool packedEntry[4096];
	unsigned int RVA;
};


void pushBytes(const char* data, const size_t size, std::vector<PeLib::byte> &dest)
{
	for (size_t i = 0; i < size; i++)
		dest.push_back(data[i]);
}

template<typename T>
bool getData(const std::vector<PeLib::byte> &input, unsigned int offset, T& output)
{
	unsigned int size = sizeof(T);
	if (offset + size >= input.size()) return false;
	
	char* data = new char[size];
	for (unsigned int i = 0; i < size; i++)
		data[i] = input[offset + i];

	output = *(T*)&data[0];
	delete [] data;
	return true;
}

template<typename T>
bool putData(std::vector<PeLib::byte> &destination, unsigned int offset, const T& input)
{
	unsigned int size = sizeof(T);
	if (offset + size >= destination.size()) return false;

	auto data = (const char*)&input;
	for (unsigned int i = 0; i < size; i++)
		destination[offset + i] = data[i];
	return true;
}



class RewriteBlock // defines a block that we will rewrite (encrypt) on disk
{
public:
	virtual bool getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const = 0;
	virtual bool getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const = 0;
	virtual bool decrementEntry(unsigned int offset, unsigned int value) = 0;
};

class EntryPointRewriteBlock : public RewriteBlock
{
public:
	EntryPointRewriteBlock(PeLib::PeFile32* _header) : header(_header) { }

	virtual bool getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const
	{
		if (size > sizeof(this->header->peHeader().getAddressOfEntryPoint()))
			return false;

		// 0x18 is sizeof(Signature) + sizeof(IMAGE_FILE_HEADER), 0x10 is the offset of AddressOfEntryPoint into IMAGE_OPTIONAL_HEADER
		firstEntryRVA = this->header->mzHeader().getAddressOfPeHeader() + 0x18 + 0x10;
		firstEntryOffset = 0;
		return true;
	}

	virtual bool getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const
	{
		return false;
	}

	virtual bool decrementEntry(unsigned int offset, unsigned int value)
	{
		unsigned int original = this->header->peHeader().getAddressOfEntryPoint();
		this->header->peHeader().setAddressOfEntryPoint(static_cast<PeLib::dword>(original - value));
		return true;
	}

private:
	PeLib::PeFile32* header;
};

class PeSectionRewriteBlock : public RewriteBlock
{
public:
	PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec)
		: sec(_sec), startOffset(0), subSize(_sec->size) { }
	PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec, unsigned int _startOffset, unsigned int _subSize)
		: sec(_sec), startOffset(_startOffset), subSize(_startOffset + _subSize)
	{
		if (this->subSize > this->sec->size)
			this->subSize = this->sec->size;
	}

	virtual bool getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const
	{
		return this->getNextEntryLoc(size, this->startOffset, firstEntryRVA, firstEntryOffset);
	}

	virtual bool getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const
	{
		if (lastEntryOffset + size >= this->subSize)
			return false;

		nextEntryOffset = lastEntryOffset + size;
		nextEntryRVA = this->sec->RVA + nextEntryOffset;
		return true;
	}

	virtual bool decrementEntry(unsigned int offset, unsigned int value)
	{
		unsigned int original;
		if (!getData(this->sec->data, offset, original)) return false;
		if (!putData(this->sec->data, offset, (original - value) )) return false;
		return true;
	}

private:
	unsigned int startOffset, subSize;
	std::shared_ptr<PeSectionContents> sec;
};


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


	/* identify blocks in the file that we will encrypt */
	std::vector<std::shared_ptr<RewriteBlock>> rewriteBlocks;

	if (!targetDEPEnabled) // encrypt entry point (only possible when DEP is off)
		rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new EntryPointRewriteBlock(&peFile)));

	for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++) // encrypt sections
	{
		auto& sec = *isec;
		if (sec->name.compare(".text") == 0 ||
			sec->name.compare(".data") == 0)
			rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(sec)));
	}


	unsigned int iatRVA = peHeader.getIddIatRva();
	unsigned int iatSize = peHeader.getIddIatSize();

	if (iatRVA && iatSize)
	{
		for (auto isec = sectionContents.begin(); isec != sectionContents.end(); isec++) // encrypt IAT
		{
			auto& sec = *isec;
			if (iatRVA < sec->RVA || iatRVA >= (sec->RVA + sec->size))
				continue;

			// encrypt the table itself
			unsigned int iatOffset = iatRVA - sec->RVA;
			auto block = new PeSectionRewriteBlock(sec, iatOffset, iatSize);
			rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(block));

			// encrypt the names
			unsigned int lowestNameRVA = 0xFFFFFFFF;
			unsigned int highestNameRVA = 0;
			for (unsigned int imp = iatOffset; imp < iatOffset + iatSize; imp += 4)
			{
				unsigned int temp;
				if (!getData(sec->data, imp, temp))
					break;
				if (temp == 0) continue;
				else if (temp < lowestNameRVA) lowestNameRVA = temp;
				else if (temp > highestNameRVA) highestNameRVA = temp;
			}

			if (lowestNameRVA >= sec->RVA && highestNameRVA <= (sec->RVA + sec->size))
			{
				auto block = new PeSectionRewriteBlock(sec, lowestNameRVA - sec->RVA, highestNameRVA - sec->RVA);
				rewriteBlocks.push_back(std::shared_ptr<RewriteBlock>(block));
			}

			//unsigned int characteristics = peHeader.getCharacteristics(sec->index);
			//if (!(characteristics & IMAGE_SCN_MEM_WRITE))
				//peHeader.setCharacteristics(sec->index, characteristics | IMAGE_SCN_MEM_WRITE);

			break;
		}
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
		if (packedBlock.offsets.size() % 2 == 1)
		{
			// align on 4 byte boundary
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
		//if (sec->size != sizeOfReloc) continue;

		sec->data.clear();
		reloc.rebuild(sec->data);
		peHeader.setVirtualSize(sec->index, sec->data.size());
		peHeader.setIddBaseRelocSize(sec->data.size());

		while (sec->data.size() % 512)
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

