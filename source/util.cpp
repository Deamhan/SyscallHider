#include "util.hpp"

#include <vector>
#include "parser.hpp"

bool EnableVTMode() noexcept
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode))
		return false;

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	return SetConsoleMode(hOut, dwMode);
}

uint64_t ProcessImage(
	uint64_t address,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	std::vector<uint8_t> buffer(0x1000);
	if (!NT_SUCCESS(X64Syscall(NtReadVirtualMemory, processHandle, address, buffer.data(), buffer.size(), 0)))
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

uint64_t GetExeEntryPoint(
	NtQueryVirtualMemory64_t NtQueryVirtualMemory,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	auto size = 0x1000;
	MEMORY_BASIC_INFORMATION64 mbi;
	for (uint64_t address = 0; NT_SUCCESS(X64Syscall(NtQueryVirtualMemory, processHandle, address, 0, &mbi, sizeof(mbi), 0)); address += size)
	{
		size = std::max<uint64_t>(0x1000, mbi.RegionSize);
		if (mbi.Type != MEM_IMAGE)
			continue;

		auto ep = ProcessImage(mbi.AllocationBase, NtReadVirtualMemory, processHandle);
		if (ep != 0)
			return ep;
	}

	return 0;
}
