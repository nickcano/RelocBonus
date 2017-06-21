#include "PeLibInclude.h" // this needs to always come before Windows.h or compile error occurs

#include <Windows.h>


struct PeSectionContents
{
	bool canPack;
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

void rebaseExecutable()
{
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

	/* turn off ASLR (needed for next step) */
	peHeader.setDllCharacteristics(characteristics & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	/* request a base address of 0xFFFF0000 (which causes us to load at 0x00010000 on w7) */
	peHeader.setImageBase(0xFFFF0000);

	/* read all section contents into buffers so so we can apply relocs */
	std::ifstream file(modName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
	if (!file.is_open())
	{
		std::cerr << "Failed to read original file!" << std::endl;
		return;
	}

	std::vector<PeSectionContents> sectionContents;
	for (unsigned int sec = 0; sec < peFile.peHeader().getNumberOfSections(); sec++)
	{
		PeSectionContents sc;
		sc.index = sec;
		sc.RVA = peHeader.getVirtualAddress(sec);
		sc.size = peHeader.getSizeOfRawData(sec);
		sc.rawPointer = peHeader.getPointerToRawData(sec);
		sc.canPack = peHeader.getSectionName(sec).compare(".text") == 0;
		sc.virtualSize = peHeader.getVirtualSize(sec);

		char* block = new char[sc.size];
		file.seekg(peHeader.getPointerToRawData(sec), std::ios::beg);
		file.read(block, sc.size);

		sc.data = std::vector<PeLib::byte>(block, block + sc.size);
		sectionContents.push_back(sc);

		delete [] block;
	}

	file.close();

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

	unsigned int relocDelta = 0x10000 - requestedBase;

	auto& reloc = peFile.relocDir();
	for (unsigned int rel = 0; rel < reloc.calcNumberOfRelocations(); rel++)
	{
		unsigned int relocBlockRVA = reloc.getVirtualAddress(rel);
		unsigned int relocBlockSize = reloc.getSizeOfBlock(rel);
		unsigned int relocBlockCount = reloc.calcNumberOfRelocationData(rel);

		PeSectionContents* sc = nullptr;
		for (auto sec = sectionContents.begin(); sec != sectionContents.end(); sec++)
		{
			if (relocBlockRVA < sec->RVA || relocBlockRVA >= (sec->RVA + sec->size)) continue;
			sc = &(*sec);
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

	/* pack sections */
	int packDelta = (0x10000 - 0xFFFF0000);
	const unsigned int dataSize = 4;
	const unsigned int chunkSize = 1024 * dataSize;
	std::vector<PackedChunk> packedChunks;
	for (auto sec = sectionContents.begin(); sec != sectionContents.end(); sec++)
	{
		if (sec->canPack)
		{
			unsigned int chunks = (sec->size / chunkSize);
			for (unsigned int chunk = 0; chunk < chunks; chunk++)
			{
				unsigned int chunkStart = chunk * chunkSize;
				unsigned int chunkEnd = chunkStart + chunkSize;
				if (chunkStart >= sec->virtualSize) break;
				if (chunkEnd >= sec->virtualSize) chunkEnd = sec->virtualSize - 1;

				PackedChunk pc;
				pc.RVA = chunkStart + sec->RVA;
				ZeroMemory(&pc.packedEntry[0], sizeof(pc.packedEntry));
				for (unsigned int offset = chunkStart; offset <= chunkEnd - dataSize; offset += dataSize)
				{
					int original;
					if (!getData(sec->data, offset, original)) continue;
					if (!putData(sec->data, offset, original - packDelta)) continue;
					pc.packedEntry[offset - chunkStart] = true;
				}
				packedChunks.push_back(pc);
			}
		}
	}

	/* clear relocations */
	while (reloc.calcNumberOfRelocations()) reloc.removeRelocation(0);

	/* fill new reloc table */
	for (auto pc = packedChunks.begin(); pc != packedChunks.end(); pc++)
	{
		reloc.addRelocation();
		unsigned int rel = reloc.calcNumberOfRelocations() - 1;
		unsigned int size = 0;
		for (unsigned short offset = 0; offset < 4096; offset++)
		{
			if (pc->packedEntry[offset])
			{
				reloc.addRelocationData(rel, (IMAGE_REL_BASED_HIGHLOW << 12) | (offset & 0x0FFF));
				size++;
			}
		}

		reloc.setVirtualAddress(rel, pc->RVA);
		reloc.setSizeOfBlock(rel, (size * 2) + 8);
	}

	/* update section metadata & contents for relocs */
	bool updatedRelocs = false;
	for (auto sec = sectionContents.begin(); sec != sectionContents.end(); sec++)
	{
		if (sec->RVA != rvaOfReloc) continue;
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
	for (auto sec = sectionContents.begin(); sec != sectionContents.end(); sec++)
	{
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

