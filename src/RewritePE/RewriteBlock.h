#include <memory>
namespace PeLib { class PeFile32; };

struct PeSectionContents
{
	std::string name;
	std::vector<PeLib::byte> data;
	unsigned int index, RVA, size, virtualSize, rawPointer;
};

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
	EntryPointRewriteBlock(PeLib::PeFile32* _header);

	virtual bool getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const;
	virtual bool getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const;
	virtual bool decrementEntry(unsigned int offset, unsigned int value);

private:
	PeLib::PeFile32* header;
};

class PeSectionRewriteBlock : public RewriteBlock
{
public:
	PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec);
	PeSectionRewriteBlock(std::shared_ptr<PeSectionContents> _sec, unsigned int _startOffset, unsigned int _subSize);

	virtual bool getFirstEntryLoc(unsigned int size, unsigned int &firstEntryRVA, unsigned int &firstEntryOffset) const;
	virtual bool getNextEntryLoc(unsigned int size, unsigned int lastEntryOffset, unsigned int &nextEntryRVA, unsigned int &nextEntryOffset) const;
	virtual bool decrementEntry(unsigned int offset, unsigned int value);

private:
	unsigned int startOffset, subSize;
	std::shared_ptr<PeSectionContents> sec;
};