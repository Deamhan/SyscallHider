#include <cstdint>
#include <cstdio>
#include <exception>

#include <windows.h>

#include "parser.hpp"
#include "util.hpp"

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
	uint64_t Protect
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t Buffer,
	uint64_t NumberOfBytesToWrite,
	uint64_t NumberOfBytesWritten OPTIONAL);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;

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

		STARTUPINFOW sa = { sizeof(sa) };
		PROCESS_INFORMATION pi = {};
		std::unique_ptr<wchar_t[], void(*)(void*)> pathCopy(wcsdup(argv[1]), free);
		auto res = CreateProcessW(nullptr, pathCopy.get(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &sa, &pi);
		// ntdll!LdrDelegatedRtlUserThreadStart

		uint64_t remoteAddress = 0; 
		struct Overhead
		{
			DWORD retHandle;
			UNICODE_STRING us;
		} overhead = {};

		uint64_t stringSizeInBytes = (wcslen(argv[2]) + 1) * 2;
		uint64_t remoteSize = sizeof(Overhead) + stringSizeInBytes;
		auto status = X64Syscall(NtAllocateVirtualMemory64, pi.hProcess, &remoteAddress, 1, &remoteSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		USHORT len = (USHORT)(stringSizeInBytes - 2);
		overhead.us = { len, len, (PWCH)(remoteAddress + sizeof(Overhead)) };
		status = X64Syscall(NtWriteVirtualMemory64, pi.hProcess, remoteAddress + sizeof(Overhead), argv[2], stringSizeInBytes, 0);
		status = X64Syscall(NtWriteVirtualMemory64, pi.hProcess, remoteAddress, &overhead, sizeof(Overhead), 0);

        CONTEXT ctx = {};
        ctx.ContextFlags = 1;
        status = X64Syscall(NtQueryInformationThread64, pi.hThread, 29, &ctx, sizeof(CONTEXT), 0);

		struct StackFrame
		{
			DWORD returnAddress = 0;
			DWORD unused0;
			DWORD unused1;
			DWORD pPath;
			DWORD pModBase;
		} frame = { ctx.Eip };

		ctx.Esp -= sizeof(StackFrame);

		frame.pPath = remoteAddress + offsetof(Overhead, us);
		frame.pModBase = remoteAddress;

		status = X64Syscall(NtWriteVirtualMemory64, pi.hProcess, ctx.Esp, &frame, sizeof(frame), 0);
		auto funcPtr = GetProcAddress(GetModuleHandleA("ntdll"), "LdrLoadDll");
		ctx.Eip = (DWORD)funcPtr;
        status = X64Syscall(NtSetInformationThread64, pi.hThread, 29, &ctx, sizeof(CONTEXT), 0);

		ResumeThread(pi.hThread);

		int a = 0;
	}
	catch (const std::exception& ex)
	{
		printf("\x1b[91mError: %s\n\x1b[m", ex.what());
		return 2;
	}

	return 0;
}
