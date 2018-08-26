#include "PeLibInclude.h"

#include "RewriteBlock.h"
#include "PeRecompiler.h"
#include "VectorUtils.h"


EntryPointRewriteBlock::EntryPointRewriteBlock(std::shared_ptr<PeLib::PeFile32> _header)
	: header(_header) { }

bool EntryPointRewriteBlock::getFirstEntryLoc(uint32_t size, uint32_t &firstEntryRVA, uint32_t &firstEntryOffset) const
{
	if (size > sizeof(this->header->peHeader().getAddressOfEntryPoint()))
		return false;

	// 0x18 is sizeof(Signature) + sizeof(IMAGE_FILE_HEADER), 0x10 is the offset of AddressOfEntryPoint into IMAGE_OPTIONAL_HEADER
	firstEntryRVA = this->header->mzHeader().getAddressOfPeHeader() + 0x18 + 0x10;
	firstEntryOffset = 0;
	return true;
}

bool EntryPointRewriteBlock::getNextEntryLoc(uint32_t size, uint32_t lastEntryOffset, uint32_t &nextEntryRVA, uint32_t &nextEntryOffset) const
{
	return false;
}

bool EntryPointRewriteBlock::decrementEntry(uint32_t offset, uint32_t value)
{
	uint32_t original = this->header->peHeader().getAddressOfEntryPoint();
	this->header->peHeader().setAddressOfEntryPoint(static_cast<PeLib::dword>(original - value));
	return true;
}



BaseAddressRewriteBlock::BaseAddressRewriteBlock(std::shared_ptr<PeLib::PeFile32> _header)
	: header(_header) { }

bool BaseAddressRewriteBlock::getFirstEntryLoc(uint32_t size, uint32_t &firstEntryRVA, uint32_t &firstEntryOffset) const
{
	if (size > sizeof(this->header->peHeader().getImageBase()))
		return false;

	// 0x18 is sizeof(Signature) + sizeof(IMAGE_FILE_HEADER), 0x1C is the offset of BaseAddress into IMAGE_OPTIONAL_HEADER
	firstEntryRVA = this->header->mzHeader().getAddressOfPeHeader() + 0x18 + 0x1C;
	firstEntryOffset = 0;
	return true;
}

bool BaseAddressRewriteBlock::getNextEntryLoc(uint32_t size, uint32_t lastEntryOffset, uint32_t &nextEntryRVA, uint32_t &nextEntryOffset) const
{
	return false;
}

bool BaseAddressRewriteBlock::decrementEntry(uint32_t offset, uint32_t value)
{
	// we don't actually rewrite this before hand, so nothing to do here
	return true;
}



PeSectionRewriteBlock::PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec)
	: sec(_sec), startOffset(0), endOffset(_sec->size) { }
PeSectionRewriteBlock::PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec, uint32_t _startOffset, uint32_t _subSize)
	: sec(_sec), startOffset(_startOffset), endOffset(_startOffset + _subSize)
{
	if (this->endOffset > this->sec->size)
		this->endOffset = this->sec->size;
}

bool PeSectionRewriteBlock::getFirstEntryLoc(uint32_t size, uint32_t &firstEntryRVA, uint32_t &firstEntryOffset) const
{
	if (this->startOffset + size > this->endOffset)
		return false;
	return this->getNextEntryLoc(0, this->startOffset, firstEntryRVA, firstEntryOffset);
}

bool PeSectionRewriteBlock::getNextEntryLoc(uint32_t size, uint32_t lastEntryOffset, uint32_t &nextEntryRVA, uint32_t &nextEntryOffset) const
{
	if (lastEntryOffset + size >= this->endOffset)
		return false;

	nextEntryOffset = lastEntryOffset + size;
	nextEntryRVA = this->sec->RVA + nextEntryOffset;
	return true;
}

bool PeSectionRewriteBlock::decrementEntry(uint32_t offset, uint32_t value)
{
	uint32_t original;
	if (!getData(this->sec->data, offset, original)) return false;
	if (!putData(this->sec->data, offset, (original - value) )) return false;
	return true;
}

std::shared_ptr<RewriteBlock> PeSectionRewriteBlock::getNextMultiPassBlock(uint32_t num)
{
	// each PeSectionRewriteBlock should have only one sibling block for multi-pass,
	// offset by 2 bytes. additionally, we shouldn't multipass something which doesn't
	// have enough bytes.
	// 
	// there's one exception: on pass #2 (index == 1), if possible, we BACKTRACK a total
	// of 4 bytes (2 to get us to original spot, 2 to get us 2 bytes before original spot) so
	// we don't miss the first 2 bytes of the data, since they'll be missed due to endianness.
	// this is mostly useful for strings and crap. This backtrack block will only be 4 bytes long,
	// as we only want to hit the first entry.

	if (num >= 1)
	{
		if (num == 1 && this->startOffset >= 4)  // backtrack for first 2 bytes
			return std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(this->sec, this->startOffset - 4, 4));
		return nullptr; // no more blocks to be made
	}
	if (this->endOffset - this->startOffset <= 6) // make sure we have room
		return nullptr;

	// first block
	auto _startOffset = this->startOffset + 2;
	return std::shared_ptr<RewriteBlock>(new PeSectionRewriteBlock(this->sec, _startOffset, this->endOffset - _startOffset));
}