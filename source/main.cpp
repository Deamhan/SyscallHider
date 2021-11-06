#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <climits>
#include <map>
#include <memory>
#include <vector>

#include <windows.h>

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
		if (mOk != FALSE)
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
	fread(buffer.data(), 1, size, pFile);

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

static auto ParseNtdll(const std::vector<uint8_t>& buffer)
{
	std::map<std::string, uint32_t> result;

	auto pDosHeader = (const IMAGE_DOS_HEADER*)buffer.data();
	auto pNtHeader = (const IMAGE_NT_HEADERS64*)(buffer.data() + pDosHeader->e_lfanew);

	std::vector<IMAGE_SECTION_HEADER> sections(pNtHeader->FileHeader.NumberOfSections);
	memcpy(sections.data(), pNtHeader + 1, sections.size() * sizeof(IMAGE_SECTION_HEADER));

	auto exportDirOffset = RVAtoOffset(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sections);
	auto exportDir = (const IMAGE_EXPORT_DIRECTORY*)(buffer.data() + exportDirOffset);
	auto pNamesOffset = RVAtoOffset(exportDir->AddressOfNames, sections);
	auto pNamesToIndexOffset = RVAtoOffset(exportDir->AddressOfNameOrdinals, sections);
	auto pFuncOffset = RVAtoOffset(exportDir->AddressOfFunctions, sections);

	auto pNames = (const uint32_t*)(buffer.data() + pNamesOffset);
	auto pFunc = (const uint32_t*)(buffer.data() + pFuncOffset);
	auto pNamesToIndex = (const uint16_t*)(buffer.data() + pNamesToIndexOffset);

	for (size_t i = 0; i < exportDir->NumberOfNames; ++i)
	{
		auto nameOffset = RVAtoOffset(pNames[i], sections);
		auto funcOffset = RVAtoOffset(pFunc[pNamesToIndex[i]], sections);
		std::string name = (const char*)(buffer.data() + nameOffset);
		if (name.compare(0, 2, "Nt") == 0)
			result.emplace(std::move(name), funcOffset);
	}
		
	return result;
}

const uint32_t PAGE_SIZE = 4096;

static uint8_t* GetNtdllCode(std::map<std::string, uint32_t>& functions, const std::vector<uint8_t>& buffer)
{
	uint32_t lower = std::numeric_limits<uint32_t>::max(),
		upper = 0;
	for (const auto& item : functions)
	{
		lower = std::min(item.second, lower);
		upper = std::max(item.second + PAGE_SIZE, upper);
	}

	auto size = upper - lower;
	auto execBuffer = (uint8_t*)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(execBuffer, buffer.data() + lower, size);

	for (auto& item : functions)
		item.second -= lower;

	return execBuffer;
}

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtQueryVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t MemoryInformationClass,
	uint64_t MemoryInformation,
	uint64_t MemoryInformationLength,
	uint64_t ReturnLength
);

#if !_X64_
extern "C" NTSTATUS X64Function(uint64_t Func, uint32_t Argc, uint64_t Arg0, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, ...);
#endif // _X64_

template <class Func, class... Args>
NTSTATUS X64Syscall(Func func, Args... args)
{
#if _X64_
	typedef NTSTATUS(NTAPI* Func_t)(Args...);
	return ((Func_t)func)(args...);
#else
	return X64Function((uint64_t)func, sizeof...(args), (uint64_t)args...);
#endif // _X64_
}

int main()
{
	std::vector<uint8_t> ntdllBuffer;
	if (!ReadNtdll(ntdllBuffer))
		return 1;

	auto functionMap = ParseNtdll(ntdllBuffer);
	auto code = GetNtdllCode(functionMap, ntdllBuffer);

	auto NtQueryVirtualMemory64 = (NtQueryVirtualMemory64_t)(code + functionMap["NtQueryVirtualMemory"]);
	MEMORY_BASIC_INFORMATION64 mbi = {};
	auto status = X64Syscall(NtQueryVirtualMemory64, GetCurrentProcess(), code, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);

	VirtualFree(code, 0, MEM_FREE);

	return 0;
}