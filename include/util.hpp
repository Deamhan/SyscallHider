#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
#include <Windows.h>

#include "parser.hpp"

#undef max
#undef min

typedef NTSTATUS(NTAPI* NtQueryInformationThread64_t)(
	uint64_t ThreadHandle,
	uint64_t ThreadInformationClass,
	uint64_t pThreadInformation,
	uint64_t ThreadInformationLength,
	uint64_t pReturnLength);

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

typedef NTSTATUS(NTAPI* NtReadVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t Buffer,
	uint64_t NumberOfBytesToRead,
	uint64_t pNumberOfBytesReaded);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t pBaseAddress,
	uint64_t pNumberOfBytesToProtect,
	uint64_t NewAccessProtection,
	uint64_t pOldAccessProtection);

enum MEMORY_INFORMATION_CLASS 
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation,
	MemoryWorkingSetExList
};

typedef NTSTATUS(NTAPI* NtQueryVirtualMemory64_t)(
	uint64_t ProcessHandle,
	uint64_t BaseAddress,
	uint64_t MemoryInformationClass,
	uint64_t MemoryInformation,
	uint64_t MemoryInformationLength,
	uint64_t ReturnLength);

typedef ULONG(NTAPI* RtlNtStatusToDosError_t)(NTSTATUS Status);

typedef NTSTATUS(NTAPI* NtCreateThreadEx64_t)(
	uint64_t hThread,
	uint64_t DesiredAccess,
	uint64_t ObjectAttributes,
	uint64_t ProcessHandle,
	uint64_t lpStartAddress,
	uint64_t lpParameter,
	uint64_t Flags,
	uint64_t StackZeroBits,
	uint64_t SizeOfStackCommit,
	uint64_t SizeOfStackReserve,
	uint64_t lpBytesBuffer);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

using HandleGuard = std::unique_ptr<std::remove_pointer_t<HANDLE>, BOOL (WINAPI*)(HANDLE)>;

void EnableVTMode();

std::tuple<uint64_t, uint64_t, bool> GetProcessInfo(
	NtQueryVirtualMemory64_t NtQueryVirtualMemory,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle);

std::vector<uint8_t> GetCodeBuffer(bool isAMD64, const std::string& dllPath, const std::string& funcName,
	const std::string& argName, uint64_t ep, uint64_t pLdrLoadDll, uint32_t argsCount);

#define GET_SYSCALL_PTR(dll, name) GetSyscallPtr<name##64_t>(dll.first, dll.second, UnscrambleString(name##Scrambled).c_str())

#define GET_NTDLL_FUNCTION(function) (function##_t)GetProcAddress(GetModuleHandleA(UnscrambleString(NtdllScrambled).c_str()), \
	UnscrambleString(function##Scrambled).c_str());

bool EnableDebugPrivilege();
