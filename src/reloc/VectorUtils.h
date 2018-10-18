#include <vector>

template<typename TI>
void pushBytes(const char* data, const size_t size, std::vector<TI> &dest)
{
	for (size_t i = 0; i < size; i++)
		dest.push_back(data[i]);
}

template<typename T, typename TI>
bool getData(const std::vector<TI> &input, unsigned int offset, T& output)
{
	unsigned int size = sizeof(T);
	if (offset + size >= input.size())
		return false;
	
	char* data = new char[size];
	for (unsigned int i = 0; i < size; i++)
		data[i] = input[offset + i];

	output = *(T*)&data[0];
	delete [] data;
	return true;
}

template<typename T, typename TI>
bool putData(std::vector<TI> &destination, unsigned int offset, const T& input)
{
	unsigned int size = sizeof(T);
	if (offset + size >= destination.size())
		return false;

	auto data = (const char*)&input;
	for (unsigned int i = 0; i < size; i++)
		destination[offset + i] = data[i];
	return true;
}