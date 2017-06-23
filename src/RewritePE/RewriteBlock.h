#pragma once

#include <stdint.h>
#include <memory>
namespace PeLib { class PeFile32; };

struct PeSectionContents;

class RewriteBlock // defines a block that we will rewrite (encrypt) on disk
{
public:
	virtual bool getFirstEntryLoc(uint32_t size, uint32_t &firstEntryRVA, uint32_t &firstEntryOffset) const = 0;
	virtual bool getNextEntryLoc(uint32_t size, uint32_t lastEntryOffset, uint32_t &nextEntryRVA, uint32_t &nextEntryOffset) const = 0;
	virtual bool decrementEntry(uint32_t offset, uint32_t value) = 0;
};

class EntryPointRewriteBlock : public RewriteBlock
{
public:
	EntryPointRewriteBlock(std::shared_ptr<PeLib::PeFile32> _header);

	virtual bool getFirstEntryLoc(uint32_t size, uint32_t &firstEntryRVA, uint32_t &firstEntryOffset) const;
	virtual bool getNextEntryLoc(uint32_t size, uint32_t lastEntryOffset, uint32_t &nextEntryRVA, uint32_t &nextEntryOffset) const;
	virtual bool decrementEntry(uint32_t offset, uint32_t value);

private:
	std::shared_ptr<PeLib::PeFile32> header;
};

class PeSectionRewriteBlock : public RewriteBlock
{
public:
	PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec);
	PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec, uint32_t _startOffset, uint32_t _subSize);

	virtual bool getFirstEntryLoc(uint32_t size, uint32_t &firstEntryRVA, uint32_t &firstEntryOffset) const;
	virtual bool getNextEntryLoc(uint32_t size, uint32_t lastEntryOffset, uint32_t &nextEntryRVA, uint32_t &nextEntryOffset) const;
	virtual bool decrementEntry(uint32_t offset, uint32_t value);

private:
	uint32_t startOffset, subSize;
	std::shared_ptr<PeSectionContents> sec;
};