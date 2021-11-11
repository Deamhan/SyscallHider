#include "util.hpp"

#include <array>
#include <cinttypes>
#include <string>
#include <vector>

#include "parser.hpp"

void EnableVTMode()
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE)
		throw std::system_error(GetLastError(), std::system_category());

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode))
		throw std::system_error(GetLastError(), std::system_category());

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	if (!SetConsoleMode(hOut, dwMode))
		throw std::system_error(GetLastError(), std::system_category());
}

template <class OptHeader>
inline uint64_t GetEntryPoint(BufferSafeAccessor& accessor, uint64_t address)
{
	auto optHeader = accessor.GetPointer<OptHeader>();
	return address + optHeader->AddressOfEntryPoint;
}

std::pair<uint64_t, bool> ProcessImage(
	uint64_t address,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	std::vector<uint8_t> buffer(0x1000);
	auto status = X64Syscall(NtReadVirtualMemory, processHandle, address, buffer.data(), buffer.size(), 0);
	if (!NT_SUCCESS(status))
		return { 0, false };

	try
	{
		BufferSafeAccessor accessor(buffer);
		auto dos = accessor.GetPointer<IMAGE_DOS_HEADER>();
		if (dos->e_magic != 0x5a4d)
			return { 0, false };

		auto signature = accessor.Seek(dos->e_lfanew).GetPointer<uint32_t>();
		if (*signature != 0x4550)
			return { 0, false };

		auto fileHeader = accessor.GetPointer<IMAGE_FILE_HEADER>();
		if ((fileHeader->Characteristics & IMAGE_FILE_DLL) != 0)
			return { 0, false };

		switch (fileHeader->Machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			return { GetEntryPoint<IMAGE_OPTIONAL_HEADER32>(accessor, address), false };
		case IMAGE_FILE_MACHINE_AMD64:
			return { GetEntryPoint<IMAGE_OPTIONAL_HEADER64>(accessor, address), true };
		default:
			return { 0, false };
		}
	}
	catch (const std::out_of_range&)
	{
		return { 0, false };
	}
}

const uint32_t PAGE_SIZE = 4096;

std::pair<uint64_t, bool> GetExeEntryPoint(
	NtQueryVirtualMemory64_t NtQueryVirtualMemory,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	uint64_t size = PAGE_SIZE;
	MEMORY_BASIC_INFORMATION64 mbi;
	for (uint64_t address = 0; NT_SUCCESS(X64Syscall(NtQueryVirtualMemory, processHandle, address, 0, &mbi, sizeof(mbi), 0)); address += size)
	{
		size = std::max<uint64_t>(PAGE_SIZE, mbi.RegionSize);
		if (mbi.Type != MEM_IMAGE)
			continue;

		auto ep = ProcessImage(mbi.AllocationBase, NtReadVirtualMemory, processHandle);
		if (ep.first != 0)
			return ep;
	}

	return { 0, false };
}

static const uint8_t injectedCode64[] = {
	0x48, 0x89, 0xE5,                                           // mov  rbp, rsp
	0x48, 0x83, 0xE4, 0xF0,                                     // mov  rsp, 0xfffffffffffffff0
	0x48, 0xB9, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov  rcx, 0x1234567890abcdef
	0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov  rax, 0x1234567890abcdef
	0x48, 0x83, 0xEC, 0x20,                                     // sub  rsp, 0x20
	0xFF, 0xD0,                                                 // call rax
	0x48, 0x05, 0x78, 0x56, 0x34, 0x12,                         // add  rax, 0x12345678
	0xFF, 0xD0,                                                 // call rax
	0x48, 0x83, 0xC4, 0x20,                                     // add  rsp, 0x20
	0xC3                                                        // ret
};

static const uint8_t injectedCode32[] = {
	0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
	0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
	0xFF, 0xD0,                   // call eax
	0x05, 0x78, 0x56, 0x34, 0x12, // add eax, 0x12345678
	0xFF, 0xD0,                   // call eax
	0xC3                          // ret
};

template <bool isAMD64>
struct arch_traits_t
{
	static const size_t StringAddressOffset = 9;
	static const size_t LoadLibraryAddressOffset = 19;
	static const size_t FuncRVAOffset = 35;

	static constexpr auto GetInjectedCode()
	{
		return std::pair<const uint8_t*, size_t>(injectedCode64, sizeof(injectedCode64));
	}

	typedef uint64_t ptr_t;
};

template <>
struct arch_traits_t<false>
{
	static const size_t StringAddressOffset = 1;
	static const size_t LoadLibraryAddressOffset = 6;
	static const size_t FuncRVAOffset = 13;

	static constexpr auto GetInjectedCode()
	{
		return std::pair<const uint8_t*, size_t>(injectedCode64, sizeof(injectedCode64));
	}

	typedef uint32_t ptr_t;
};

template <bool isAMD64>
std::vector<uint8_t> GetCodeBuffer(const std::string& dllPath, const std::string& funcName, uintptr_t ep)
{
	typedef typename arch_traits_t<isAMD64>::ptr_t ptr_t;

	size_t stringSizeInBytes = dllPath.length() + 1;
	auto [codeBuffer, codeSize] = arch_traits_t<isAMD64>::GetInjectedCode();

	std::vector<uint8_t> epNewBytes(codeSize + stringSizeInBytes);
	memcpy(epNewBytes.data(), codeBuffer, codeSize);
	memcpy(epNewBytes.data() + codeSize, dllPath.c_str(), stringSizeInBytes);

	*(ptr_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::StringAddressOffset) = ep + codeSize;
	auto funcPtr = (ptr_t)GetProcAddress(GetModuleHandleA("kernelbase"), "LoadLibraryA"); // FIXME
	*(ptr_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::LoadLibraryAddressOffset) = funcPtr;

	auto hModule = LoadLibraryA(dllPath.c_str());
	if (hModule == nullptr)
		throw std::system_error(GetLastError(), std::system_category(),
			std::string("unable to load module \'").append(dllPath).append("\'"));

	auto funcToRun = GetProcAddress(hModule, funcName.c_str());
	if (funcToRun == nullptr)
		throw std::logic_error(dllPath + "!" + funcName + " does not exist");

	*(uint32_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::FuncRVAOffset) = (uint32_t)((uintptr_t)funcToRun - (uintptr_t)hModule);

	return epNewBytes;
}

template std::vector<uint8_t> GetCodeBuffer<false>(const std::string& dllPath, const std::string& funcName, uintptr_t ep);
template std::vector<uint8_t> GetCodeBuffer<true>(const std::string& dllPath, const std::string& funcName, uintptr_t ep);
