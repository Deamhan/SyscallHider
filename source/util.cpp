#include "util.hpp"

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

uint64_t ProcessImage(
	uint64_t address,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	std::vector<uint8_t> buffer(0x1000);
	auto status = X64Syscall(NtReadVirtualMemory, processHandle, address, buffer.data(), buffer.size(), 0);
	if (!NT_SUCCESS(status))
		return 0;

	try
	{
		BufferSafeAccessor accessor(buffer);
		auto dos = accessor.GetPointer<IMAGE_DOS_HEADER>();
		if (dos->e_magic != 0x5a4d)
			return 0;

		auto nt = accessor.Seek(dos->e_lfanew).GetPointer<IMAGE_NT_HEADERS>();
		if (nt->Signature != 0x4550)
			return 0;

		if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
			return 0;

		return address + nt->OptionalHeader.AddressOfEntryPoint;
	}
	catch (const std::out_of_range&)
	{
		return 0;
	}
}

const uint32_t PAGE_SIZE = 4096;

uintptr_t GetExeEntryPoint(
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
		if (ep != 0)
			return (uintptr_t)ep;
	}

	return 0;
}

#ifndef _X64_
static const uint8_t injectedCode[] = {
	0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
	0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
	0xFF, 0xD0,                   // call eax
	0x05, 0x78, 0x56, 0x34, 0x12, // add eax, 0x12345678
	0xFF, 0xD0,                   // call eax
	0xC3                          // ret
};

static const uintptr_t StringAddressOffset = 1;
static const uintptr_t LoadLibraryAddressOffset = 6;
static const uintptr_t FuncRVAOffset = 13;

#else
static const uint8_t injectedCode[] = {
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

static const uintptr_t StringAddressOffset = 9;
static const uintptr_t LoadLibraryAddressOffset = 19;
static const uintptr_t FuncRVAOffset = 35;
#endif // _X64_

std::vector<uint8_t> GetCodeBuffer(const std::string& dllPath, const std::string& funcName, uintptr_t ep)
{
	uintptr_t stringSizeInBytes = dllPath.length() + 1;
	std::vector<uint8_t> epNewBytes(sizeof(injectedCode) + stringSizeInBytes);
	memcpy(epNewBytes.data(), injectedCode, sizeof(injectedCode));
	memcpy(epNewBytes.data() + sizeof(injectedCode), dllPath.c_str(), stringSizeInBytes);

	*(uintptr_t*)(epNewBytes.data() + StringAddressOffset) = ep + sizeof(injectedCode);
	auto funcPtr = (uintptr_t)GetProcAddress(GetModuleHandleA("kernelbase"), "LoadLibraryA");
	*(uintptr_t*)(epNewBytes.data() + LoadLibraryAddressOffset) = funcPtr;

	auto hModule = LoadLibraryA(dllPath.c_str());
	if (hModule == nullptr)
		throw std::system_error(GetLastError(), std::system_category(),
			std::string("unable to load module \'").append(dllPath).append("\'"));

	auto funcToRun = GetProcAddress(hModule, funcName.c_str());
	if (funcToRun == nullptr)
		throw std::logic_error(dllPath + "!" + funcName + " does not exist");

	*(uint32_t*)(epNewBytes.data() + FuncRVAOffset) = (uint32_t)((uintptr_t)funcToRun - (uintptr_t)hModule);

	return epNewBytes;
}

