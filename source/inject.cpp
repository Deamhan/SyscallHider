#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <utility>

#include "cmdline.hpp"
#include "util.hpp"

static CmdLineOptionValue gExec = {}, gDll = {}, gFunc = {}, gArg = {};

static const std::vector<CmdLineOption> gCmdLineOptions
{
	{ 'e', "Exec",     "Exec file to run and inject",       "",        true,  gExec },
	{ 'd', "DLL",      "DLL payload",                       "",        true,  gDll  },
	{ 'f', "Function", "Function from payload DLL to call", "Handler", false, gFunc },
	{ 'a', "Arg",      "Argument provider function",        "Arg",     false, gArg  },
};

static const char* coloredErrorPattern = "\x1b[91mError: %s\n\x1b[m";
static const char* simpleErrorPattern = "Error: %s\n";

int main(int argc, const char** argv)
{
	const char* errPattern = simpleErrorPattern;
	PROCESS_INFORMATION pi = {};
	std::unique_ptr<PROCESS_INFORMATION, void(*)(PROCESS_INFORMATION*)> processInfoGuard(&pi, [](PROCESS_INFORMATION* pi)
		{
			CloseHandle(pi->hProcess);
			CloseHandle(pi->hThread);
		});

	try
	{
		EnableVTMode();
		errPattern = coloredErrorPattern;
		ParseCmdLine(gCmdLineOptions, argc, argv);

		STARTUPINFOA sa = { sizeof(sa) };
		
		std::unique_ptr<char[], void(*)(void*)> pathCopy(strdup(gExec.first.c_str()), free);
		auto res = CreateProcessA(nullptr, pathCopy.get(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &sa, &pi);
		if (!res)
			throw std::system_error(GetLastError(), std::system_category(),
				std::string("unable to run target process \'").append(pathCopy.get()).append("\'"));

		auto ntdll = ParseNtdll();
		auto NtSetInformationThread64 = GET_SYSCALL_PTR(ntdll, NtSetInformationThread);
		auto NtQueryInformationThread64 = GET_SYSCALL_PTR(ntdll, NtQueryInformationThread);
		auto NtAllocateVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtAllocateVirtualMemory);
		auto NtWriteVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtWriteVirtualMemory);
		auto NtReadVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtReadVirtualMemory);
		auto NtQueryVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtQueryVirtualMemory);
		auto NtProtectVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtProtectVirtualMemory);

		auto [ep, pLdrLoadDll, isAMD64] = GetProcessInfo(NtQueryVirtualMemory64, NtReadVirtualMemory64, (uint64_t)pi.hProcess);
		auto epNewBytes = GetCodeBuffer(isAMD64, gDll.first, gFunc.first, gArg.first, ep, pLdrLoadDll);

		uint64_t addressToVProt = ep;
		uint64_t sizeToVProt = epNewBytes.size();
		uint64_t oldVProt = 0;

		
		auto RtlNtStatusToDosError = GET_NTDLL_FUNCTION(RtlNtStatusToDosError);
		auto CheckStatus = [RtlNtStatusToDosError](NTSTATUS Status, HANDLE hProc)
		{
			if (NT_SUCCESS(Status))
				return;

			throw std::system_error(RtlNtStatusToDosError(Status), std::generic_category(), "native api call failed");
		};

		CheckStatus(X64Syscall(NtProtectVirtualMemory64, pi.hProcess, &addressToVProt, &sizeToVProt, PAGE_EXECUTE_READWRITE, &oldVProt), pi.hProcess);
		CheckStatus(X64Syscall(NtWriteVirtualMemory64, pi.hProcess, ep, epNewBytes.data(), epNewBytes.size(), 0), pi.hProcess);

		ResumeThread(pi.hThread);
	}
	catch (const std::exception& ex)
	{
		if (pi.hProcess != nullptr)
			TerminateProcess(pi.hProcess, 0);

		printf(errPattern, ex.what());
		return 1;
	}

	return 0;
}
