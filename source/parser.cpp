#include "parser.hpp"

#undef min
#undef max

static bool ReadDll(const fs::path& path, std::vector<uint8_t>& buffer)
{
	std::error_code ec;
	auto size = fs::file_size(path, ec);
	if (ec || size == 0)
		return false;

	buffer.resize(size);
	FILE* pFile = nullptr;
	if (_wfopen_s(&pFile, path.wstring().c_str(), L"rb") != 0)
		return false;

	std::unique_ptr<FILE, int(*)(FILE*)> file(pFile, fclose);
	fread(buffer.data(), 1, size, file.get());

	return true;
}

fs::path GetDllPath(std::string_view name, bool isWOW64)
{
	char windirBuffer[128] = {};
	auto res = GetEnvironmentVariableA("WINDIR", windirBuffer, 128);
	if (res == 0)
		throw std::system_error(GetLastError(), std::generic_category(), "unable to get %WINDIR% value");

	fs::path dllPath(windirBuffer);
	dllPath /= isWOW64 ? "SysWOW64" : "System32";
	dllPath /= name;

	return dllPath;
}

static bool ReadNtdll(std::vector<uint8_t>& buffer)
{
	Wow64RedirectionDisabler disabler;

	fs::path ntdllPath = GetDllPath("ntdll.dll", false);

	return ReadDll(ntdllPath, buffer);
}

template <bool isMapped>
static uint32_t RVAtoOffset(uint32_t rva, const std::vector<IMAGE_SECTION_HEADER>& sections)
{
	for (const auto& section : sections)
	{
		if (section.VirtualAddress <= rva && rva < section.VirtualAddress + section.Misc.VirtualSize)
			return section.PointerToRawData + (rva - section.VirtualAddress);
	}

	return 0;
}

template <>
static uint32_t RVAtoOffset<true>(uint32_t rva, const std::vector<IMAGE_SECTION_HEADER>& /*sections*/)
{
	return rva;
}

template <bool isAMD64>
struct arch_traits_t
{
	typedef IMAGE_OPTIONAL_HEADER64 opt_header_t;	
};

template <>
struct arch_traits_t<false>
{
	typedef IMAGE_OPTIONAL_HEADER32 opt_header_t;
};

template <bool isAMD64, bool isMappedImage>
static void ParseDllExportArchSpecific(BufferSafeAccessor& buffer, const IMAGE_FILE_HEADER * pFileHeader,
	syscall_map& result, IFilter& filter, bool getExportByRVA)
{
	typedef typename arch_traits_t<isAMD64>::opt_header_t opt_header_t;

	auto optHeader = buffer.GetPointer<opt_header_t>();
	auto pSections = buffer.GetPointer<IMAGE_SECTION_HEADER>(pFileHeader->NumberOfSections);
	std::vector<IMAGE_SECTION_HEADER> sections(pSections, pSections + pFileHeader->NumberOfSections);
	auto exportDirOffset = RVAtoOffset<isMappedImage>(optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sections);
	auto exportDir = buffer.Seek(exportDirOffset).GetPointer<IMAGE_EXPORT_DIRECTORY>();
	auto namesOffset = RVAtoOffset<isMappedImage>(exportDir->AddressOfNames, sections);
	auto namesToIndexOffset = RVAtoOffset<isMappedImage>(exportDir->AddressOfNameOrdinals, sections);
	auto funcOffset = RVAtoOffset<isMappedImage>(exportDir->AddressOfFunctions, sections);

	auto pNames = buffer.Seek(namesOffset).GetPointer<uint32_t>(exportDir->NumberOfNames);
	auto pFunc = buffer.Seek(funcOffset).GetPointer<uint32_t>(exportDir->NumberOfFunctions);
	auto pNamesToIndex = buffer.Seek(namesToIndexOffset).GetPointer<uint16_t>(exportDir->NumberOfNames);

	for (size_t i = 0; i < exportDir->NumberOfNames; ++i)
	{
		auto nameOffset = RVAtoOffset<isMappedImage>(pNames[i], sections);
		auto nameToFunc = pNamesToIndex[i];
		if (nameToFunc >= exportDir->NumberOfFunctions)
			continue;

		auto funcOffsetOrRva = getExportByRVA ? pFunc[nameToFunc] : RVAtoOffset<isMappedImage>(pFunc[nameToFunc], sections);
		auto name = buffer.Seek(nameOffset).GetString();
		if (filter(name))
			result.emplace(name, funcOffsetOrRva);
	}
}

template <bool isMappedImage>
syscall_map ParseDllExport(BufferSafeAccessor buffer, IFilter& filter, bool getExportByRVA)
{
	syscall_map result;

	try
	{
		auto pDosHeader = buffer.GetPointer<IMAGE_DOS_HEADER>();
		if (pDosHeader->e_magic != 0x5a4d)
			throw std::logic_error("invalid PE file");

		auto signature = *(buffer.Seek(pDosHeader->e_lfanew).GetPointer<uint32_t>());
		if (signature != 0x4550)
			throw std::logic_error("invalid PE file");

		auto pFileHeader = buffer.GetPointer<IMAGE_FILE_HEADER>();
		switch (pFileHeader->Machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			ParseDllExportArchSpecific<false, isMappedImage>(buffer, pFileHeader, result, filter, getExportByRVA);
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			ParseDllExportArchSpecific<true, isMappedImage>(buffer, pFileHeader, result, filter, getExportByRVA);
			break;
		default:
			throw std::logic_error("Unsupported architecture");
		}
	}
	catch (const std::out_of_range&)
	{
		throw std::exception("unable to parse DLL");
	}

	return result;
}

template syscall_map ParseDllExport<true>(BufferSafeAccessor buffer, IFilter& filter, bool getExportByRVA);
template syscall_map ParseDllExport<false>(BufferSafeAccessor buffer, IFilter& filter, bool getExportByRVA);

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

	class SyscallFilter : public IFilter
	{
		bool Filter(std::string_view name) override
		{
			return (name.compare(0, 2, "Nt") == 0);
		}
	} filter;
	auto functions = ParseDllExport<false>(buffer, filter, false);
	return { GetNtdllCode(functions, buffer), functions };
}

template <bool isMappedImage>
syscall_map ParseDllExport(const fs::path& path, IFilter& filter, bool getExportByRVA)
{
	syscall_map result;
	std::vector<uint8_t> buffer;
	if (!ReadDll(path, buffer))
		return result;

	return ParseDllExport<isMappedImage>(buffer, filter, getExportByRVA);
}

template syscall_map ParseDllExport<true>(const fs::path& path, IFilter& filter, bool getExportByRVA);
template syscall_map ParseDllExport<false>(const fs::path& path, IFilter& filter, bool getExportByRVA);
