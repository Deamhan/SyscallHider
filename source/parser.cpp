#include "parser.hpp"

#undef min
#undef max

namespace fs = std::filesystem;

class Wow64RedirectionDisabler
{
#ifndef _X64_
	PVOID mOldValue;
	BOOL  mOk;
public:
	Wow64RedirectionDisabler() noexcept
	{
		mOk = Wow64DisableWow64FsRedirection(&mOldValue);
	}

	~Wow64RedirectionDisabler()
	{
		if (mOk)
			Wow64RevertWow64FsRedirection(mOldValue);
	}
#endif
};

static bool ReadNtdll(std::vector<uint8_t>& buffer)
{
	Wow64RedirectionDisabler disabler;

	wchar_t windirBuffer[128] = {};
	auto res = GetEnvironmentVariableW(L"WINDIR", windirBuffer, 128);
	if (res == 0)
		return false;

	fs::path ntdllPath(windirBuffer);
	ntdllPath /= LR"(system32\ntdll.dll)";

	std::error_code ec;
	auto size = fs::file_size(ntdllPath, ec);
	if (ec || size == 0)
		return false;

	buffer.resize(size);
	FILE* pFile = nullptr;
	if (_wfopen_s(&pFile, ntdllPath.wstring().c_str(), L"rb") != 0)
		return false;

	std::unique_ptr<FILE, int(*)(FILE*)> file(pFile, fclose);
	fread(buffer.data(), 1, size, file.get());

	return true;
}

static uint32_t RVAtoOffset(uint32_t rva, const std::vector<IMAGE_SECTION_HEADER>& sections)
{
	for (const auto& section : sections)
	{
		if (section.VirtualAddress >= rva && rva < section.VirtualAddress + section.Misc.VirtualSize)
			return section.PointerToRawData + (rva - section.VirtualAddress);
	}

	return 0;
}

class BufferSafeAccessor
{
	const std::vector<uint8_t>& mBuffer;
	size_t mPosition;
public:
	BufferSafeAccessor(const std::vector<uint8_t>& buffer) : mBuffer(buffer), mPosition(0) {}

	template <class T>
	const T* GetPointer(size_t count = 1)
	{
		const auto startPosition = mPosition;
		mPosition += sizeof(T) * count;
		if (mBuffer.size() < mPosition)
		{
			mPosition = startPosition;
			throw std::out_of_range("buffer is not long enough");
		}

		return (const T*)(&mBuffer[startPosition]);
	}

	std::string_view GetString()
	{
		const size_t startPosition = mPosition;
		for (; mPosition < mBuffer.size(); ++mPosition)
		{
			if (mBuffer[mPosition] == 0)
				return std::string_view((const char*)&mBuffer[startPosition], mPosition - startPosition);
		}

		mPosition = startPosition;
		throw std::out_of_range("unable to find string end");
	}

	BufferSafeAccessor& Seek(size_t position)
	{
		if (position > mBuffer.size())
			throw std::out_of_range("buffer is not long enough");

		mPosition = position;
		return *this;
	}
};

static syscall_map ParseNtdllExport(BufferSafeAccessor buffer)
{
	syscall_map result;

	try
	{
		auto pDosHeader = buffer.GetPointer<IMAGE_DOS_HEADER>();
		auto pNtHeader = buffer.Seek(pDosHeader->e_lfanew).GetPointer<IMAGE_NT_HEADERS64>();
		auto pSections = buffer.GetPointer<IMAGE_SECTION_HEADER>(pNtHeader->FileHeader.NumberOfSections);

		std::vector<IMAGE_SECTION_HEADER> sections(pSections, pSections + pNtHeader->FileHeader.NumberOfSections);
		auto exportDirOffset = RVAtoOffset(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sections);
		auto exportDir = buffer.Seek(exportDirOffset).GetPointer<IMAGE_EXPORT_DIRECTORY>();
		auto namesOffset = RVAtoOffset(exportDir->AddressOfNames, sections);
		auto namesToIndexOffset = RVAtoOffset(exportDir->AddressOfNameOrdinals, sections);
		auto funcOffset = RVAtoOffset(exportDir->AddressOfFunctions, sections);

		auto pNames = buffer.Seek(namesOffset).GetPointer<uint32_t>(exportDir->NumberOfNames);
		auto pFunc = buffer.Seek(funcOffset).GetPointer<uint32_t>(exportDir->NumberOfFunctions);
		auto pNamesToIndex = buffer.Seek(namesToIndexOffset).GetPointer<uint16_t>(exportDir->NumberOfNames);

		for (size_t i = 0; i < exportDir->NumberOfNames; ++i)
		{
			auto nameOffset = RVAtoOffset(pNames[i], sections);
			auto nameToFunc = pNamesToIndex[i];
			if (nameToFunc >= exportDir->NumberOfFunctions)
				continue;

			auto funcOffset = RVAtoOffset(pFunc[nameToFunc], sections);
			auto name = buffer.Seek(nameOffset).GetString();
			if (name.compare(0, 2, "Nt") == 0)
				result.emplace(name, funcOffset);
		}
	}
	catch (const std::out_of_range&) 
	{
		throw std::exception("unable to parse ntdll");
	}

	return result;
}

const uint32_t PAGE_SIZE = 4096;

static exec_ptr_t GetNtdllCode(syscall_map& functions, const std::vector<uint8_t>& buffer)
{
	uint32_t lower = std::numeric_limits<uint32_t>::max(),
		upper = 0;
	for (const auto& item : functions)
	{
		lower = std::min(item.second, lower);
		upper = std::max(item.second + PAGE_SIZE, upper);
	}

	auto deleter = [](void* p) noexcept { VirtualFree(p, 0, MEM_FREE); };

	auto size = upper - lower;
	auto execBuffer = (uint8_t*)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	exec_ptr_t result(execBuffer, deleter);
	if (!result)
		throw std::exception("unable to allocate executable memory");

	memcpy(result.get(), buffer.data() + lower, size);

	for (auto& item : functions)
		item.second -= lower;

	return result;
}

std::pair<exec_ptr_t, syscall_map> ParseNtdll()
{
	std::vector<uint8_t> buffer;
	if (!ReadNtdll(buffer))
		throw std::exception("unable to read ntdll");

	auto functions = ParseNtdllExport(buffer);
	return { GetNtdllCode(functions, buffer), functions };
}
