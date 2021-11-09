#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>

#include <windows.h>

#include "parser.hpp"
#include "util.hpp"

#undef max

typedef NTSTATUS (NTAPI* NtQueryInformationThread64_t)(
    uint64_t ThreadHandle,
    uint64_t ThreadInformationClass,
    uint64_t pThreadInformation,
    uint64_t ThreadInformationLength,
    uint64_t pReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI* NtSetInformationThread64_t)(
    uint64_t ThreadHandle,
    uint64_t ThreadInformationClass,
    uint64_t pThreadInformation,
    uint64_t ThreadInformationLength);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t pBaseAddress,
	uint64_t ZeroBits,
	uint64_t pRegionSize,
	uint64_t AllocationType,
	uint64_t Protect);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t Buffer,
	uint64_t NumberOfBytesToWrite,
	uint64_t NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(NTAPI* NtQueryVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t MemoryInformationClass,
	uint64_t MemoryInformation,
	uint64_t MemoryInformationLength,
	uint64_t pReturnLength);

typedef NTSTATUS (NTAPI* NtReadVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t Buffer,
	uint64_t NumberOfBytesToRead,
	uint64_t pNumberOfBytesReaded);

typedef NTSTATUS (NTAPI* NtProtectVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t pBaseAddress,
	uint64_t pNumberOfBytesToProtect,
	uint64_t NewAccessProtection,
	uint64_t pOldAccessProtection);



typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;

static uint64_t ProcessImage(
	uint64_t address,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	std::vector<uint8_t> buffer(0x1000);
	if (!NT_SUCCESS(X64Syscall(NtReadVirtualMemory, processHandle, address, buffer.data(), buffer.size(), 0)))
		return 0;

	BufferSafeAccessor accessor(buffer);
	auto dos = accessor.GetPointer<IMAGE_DOS_HEADER>();
	auto nt = accessor.Seek(dos->e_lfanew).GetPointer<IMAGE_NT_HEADERS>();
	if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
		return 0;

	return address + nt->OptionalHeader.AddressOfEntryPoint;
}

static uint64_t GetExeEntryPoint(
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

int wmain(int argc, const wchar_t** argv)
{
	if (!EnableVTMode())
	{
		printf("Unable to prepare terminal\n");
		return 1;
	}

	try
	{
		auto ntdll = ParseNtdll();
		auto NtSetInformationThread64 = GET_SYSCALL_PTR(ntdll, NtSetInformationThread);
		auto NtQueryInformationThread64 = GET_SYSCALL_PTR(ntdll, NtQueryInformationThread);
		auto NtAllocateVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtAllocateVirtualMemory);
		auto NtWriteVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtWriteVirtualMemory);
		auto NtReadVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtReadVirtualMemory);
		auto NtQueryVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtQueryVirtualMemory);
		auto NtProtectVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtProtectVirtualMemory);

		STARTUPINFOW sa = { sizeof(sa) };
		PROCESS_INFORMATION pi = {};
		std::unique_ptr<wchar_t[], void(*)(void*)> pathCopy(wcsdup(argv[1]), free);
		auto res = CreateProcessW(nullptr, pathCopy.get(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &sa, &pi);
		// ntdll!LdrDelegatedRtlUserThreadStart

		auto ep = GetExeEntryPoint(NtQueryVirtualMemory64, NtReadVirtualMemory64, (uint64_t)pi.hProcess);

		uint8_t injectedCode[] = {
			0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
			0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
			0xFF, 0xD0,                   // call eax
			/*0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
			0xFF, 0xD0,                   // call eax
			0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
			0xFF, 0xD0,                   // call eax*/
			0xC3                          // ret
		};
		uint64_t stringSizeInBytes = (wcslen(argv[2]) + 1) * 2;
		std::vector<uint8_t> epNewBytes(sizeof(injectedCode) + stringSizeInBytes);
		*(uint32_t*)(injectedCode + 1) = (uint32_t)ep + sizeof(injectedCode);
		auto funcPtr = GetProcAddress(GetModuleHandleA("kernelbase"), "LoadLibraryW");
		*(uint32_t*)(injectedCode + 6) = (uint32_t)funcPtr;
		memcpy(epNewBytes.data(), injectedCode, sizeof(injectedCode));
		memcpy(epNewBytes.data() + sizeof(injectedCode), argv[2], stringSizeInBytes);

		uint64_t addressToVProt = ep;
		uint64_t sizeToVProt = epNewBytes.size();
		uint64_t oldVProt = 0;
		auto status = X64Syscall(NtProtectVirtualMemory64, pi.hProcess, &addressToVProt, &sizeToVProt, PAGE_EXECUTE_READWRITE, &oldVProt);
		status = X64Syscall(NtWriteVirtualMemory64, pi.hProcess, ep, epNewBytes.data(), epNewBytes.size(), 0);

		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	catch (const std::exception& ex)
	{
		printf("\x1b[91mError: %s\n\x1b[m", ex.what());
		return 2;
	}

	return 0;
}
