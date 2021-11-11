#include <cstdint>
#include <cstdio>
#include <exception>

#include "parser.hpp"
#include "util.hpp"

int main()
{
	if (!EnableVTMode())
	{
		printf("Unable to prepare terminal\n");
		return 1;
	}

	try
	{
		auto ntdll = ParseNtdll();

		auto NtQueryVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtQueryVirtualMemory);
		MEMORY_BASIC_INFORMATION64 mbi = {};
		auto status = X64Syscall(NtQueryVirtualMemory64, GetCurrentProcess(), ntdll.first.get(), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
		if (!NT_SUCCESS(status))
		{
			char message[512];
			sprintf(message, "NtQueryVirtualMemory failed (status = 0x%08x)", (unsigned)status);
			throw std::exception(message);
		}

		if (mbi.AllocationBase != (ULONGLONG)ntdll.first.get())
		{
			char message[512];
			sprintf(message, "Invalid data has been received from syscall");
			throw std::exception(message);
		}
	}
	catch (const std::exception& ex)
	{
		printf("\x1b[91mError: %s\n\x1b[m", ex.what());
		return 2;
	}

	printf("\x1b[92mTest has been passed!\n\x1b[m");
	return 0;
}
