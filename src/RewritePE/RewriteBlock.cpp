#include "PeLibInclude.h"

#include "RewriteBlock.h"
#include "VectorUtils.h"


EntryPointRewriteBlock::EntryPointRewriteBlock(PeLib::PeFile32* _header)
	: header(_header) { }

bool EntryPointRewriteBlock::getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const
{
	if (size > sizeof(this->header->peHeader().getAddressOfEntryPoint()))
		return false;

	// 0x18 is sizeof(Signature) + sizeof(IMAGE_FILE_HEADER), 0x10 is the offset of AddressOfEntryPoint into IMAGE_OPTIONAL_HEADER
	firstEntryRVA = this->header->mzHeader().getAddressOfPeHeader() + 0x18 + 0x10;
	firstEntryOffset = 0;
	return true;
}

bool EntryPointRewriteBlock::getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const
{
	return false;
}

bool EntryPointRewriteBlock::decrementEntry(unsigned int offset, unsigned int value)
{
	unsigned int original = this->header->peHeader().getAddressOfEntryPoint();
	this->header->peHeader().setAddressOfEntryPoint(static_cast<PeLib::dword>(original - value));
	return true;
}



PeSectionRewriteBlock::PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec)
	: sec(_sec), startOffset(0), subSize(_sec->size) { }
PeSectionRewriteBlock::PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec, unsigned int _startOffset, unsigned int _subSize)
	: sec(_sec), startOffset(_startOffset), subSize(_startOffset + _subSize)
{
	if (this->subSize > this->sec->size)
		this->subSize = this->sec->size;
}

bool PeSectionRewriteBlock::getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const
{
	if (this->startOffset + size >= this->subSize)
		return false;
	return this->getNextEntryLoc(0, this->startOffset, firstEntryRVA, firstEntryOffset);
}

bool PeSectionRewriteBlock::getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const
{
	if (lastEntryOffset + size >= this->subSize)
		return false;

	nextEntryOffset = lastEntryOffset + size;
	nextEntryRVA = this->sec->RVA + nextEntryOffset;
	return true;
}

bool PeSectionRewriteBlock::decrementEntry(unsigned int offset, unsigned int value)
{
	unsigned int original;
	if (!getData(this->sec->data, offset, original)) return false;
	if (!putData(this->sec->data, offset, (original - value) )) return false;
	return true;
}
