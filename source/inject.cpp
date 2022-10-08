#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <utility>

#include "cmdline.hpp"
#include "util.hpp"

static CmdLineOptionValue gPid = {}, gExec = {}, gDll = {}, gFunc = {}, gArg = {};

static const std::vector<CmdLineOption> gCmdLineOptions
{
	{ 'p', "Pid",      "PID of process to inject (incompatible with 'Exec' option)",          "",        false, gPid  },
	{ 'e', "Exec",     "Exec file to run and inject (incompatible with 'Pid' option)",        "",        false, gExec },
	{ 'd', "DLL",      "DLL payload",                                                         "",        true,  gDll  },
	{ 'f', "Function", "Function from payload DLL to call",                                   "Handler", false, gFunc },
	{ 'a', "Arg",      "Argument provider function",                                          "Arg",     false, gArg  },
};

static const char* coloredErrorPattern = "\x1b[91mError: %s\n\x1b[m";
static const char* simpleErrorPattern = "Error: %s\n";

static const char* coloredWarningPattern = "\x1b[93mWarning: %s\n\x1b[m";
static const char* simpleWarningPattern = "Warning: %s\n";

int main(int argc, const char** argv)
{
	const char* errPattern = simpleErrorPattern;
	const char* warnPattern = simpleWarningPattern;
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
		warnPattern = coloredWarningPattern;
		ParseCmdLine(gCmdLineOptions, argc, argv);

		if (gPid.first.empty() && gExec.first.empty())
			throw std::logic_error("either 'Pid' or 'Exec' option must be set");
		else if (!(gPid.first.empty() || gExec.first.empty()))
			throw std::logic_error("use of mutually exclusive 'Pid' and 'Exec' options");

		auto ntdll = ParseNtdll();
		auto NtSetInformationThread64 = GET_SYSCALL_PTR(ntdll, NtSetInformationThread);
		auto NtQueryInformationThread64 = GET_SYSCALL_PTR(ntdll, NtQueryInformationThread);
		auto NtAllocateVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtAllocateVirtualMemory);
		auto NtWriteVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtWriteVirtualMemory);
		auto NtReadVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtReadVirtualMemory);
		auto NtQueryVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtQueryVirtualMemory);
		auto NtProtectVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtProtectVirtualMemory);
		auto NtCreateThreadEx64 = GET_SYSCALL_PTR(ntdll, NtCreateThreadEx);

		auto RtlNtStatusToDosError = GET_NTDLL_FUNCTION(RtlNtStatusToDosError);
		auto CheckStatus = [RtlNtStatusToDosError](NTSTATUS Status)
		{
			if (NT_SUCCESS(Status))
				return;

			throw std::system_error(RtlNtStatusToDosError(Status), std::generic_category(), "native api call failed");
		};

		if (gPid.first.empty())
		{
			STARTUPINFOA sa = { sizeof(sa) };

			std::unique_ptr<char[], void(*)(void*)> pathCopy(strdup(gExec.first.c_str()), free);
			auto res = CreateProcessA(nullptr, pathCopy.get(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &sa, &pi);
			if (!res)
				throw std::system_error(GetLastError(), std::system_category(),
					std::string("unable to run target process \'").append(pathCopy.get()).append("\'"));

			

			auto [ep, pLdrLoadDll, isAMD64] = GetProcessInfo(NtQueryVirtualMemory64, NtReadVirtualMemory64, (uint64_t)pi.hProcess);
			auto epNewBytes = GetCodeBuffer(isAMD64, gDll.first, gFunc.first, gArg.first, ep, pLdrLoadDll, 0);

			uint64_t addressToVProt = ep;
			uint64_t sizeToVProt = epNewBytes.size();
			uint64_t oldVProt = 0;

			CheckStatus(X64Syscall(NtProtectVirtualMemory64, pi.hProcess, &addressToVProt, &sizeToVProt, PAGE_EXECUTE_READWRITE, &oldVProt));
			CheckStatus(X64Syscall(NtWriteVirtualMemory64, pi.hProcess, ep, epNewBytes.data(), epNewBytes.size(), 0));

			ResumeThread(pi.hThread);
		}
		else
		{
			DWORD pid = 0;
			try
			{
				pid = std::stoi(gPid.first);
				if (pid <= 0)
					throw std::exception();
			}
			catch (const std::exception&)
			{
				throw std::logic_error("'Pid' must be a positive integer");
			}
			
			if (!EnableDebugPrivilege())
				printf(warnPattern, "unable to enable debug privilege");

			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (hProcess == nullptr)
				throw std::system_error(GetLastError(), std::system_category(),
					std::string("unable to open process \'").append(gPid.first).append("\'"));

			HandleGuard processGuard(hProcess, CloseHandle);

			auto [unused, pLdrLoadDll, isAMD64] = GetProcessInfo(NtQueryVirtualMemory64, NtReadVirtualMemory64, (uint64_t)hProcess);
			auto threadEpNewBytes = GetCodeBuffer(isAMD64, gDll.first, gFunc.first, gArg.first, 0, pLdrLoadDll, 1); // ThreadProc accepts 1 argument
			uint64_t sizeToAllocate = threadEpNewBytes.size();
			uint64_t allocatedAddress = 0;
			
			CheckStatus(X64Syscall(NtAllocateVirtualMemory64, hProcess, &allocatedAddress, 0, &sizeToAllocate, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
			threadEpNewBytes = GetCodeBuffer(isAMD64, gDll.first, gFunc.first, gArg.first, allocatedAddress, pLdrLoadDll, 1); // ThreadProc accepts 1 argument

			uint64_t oldVProt = 0;
			CheckStatus(X64Syscall(NtWriteVirtualMemory64, hProcess, allocatedAddress, threadEpNewBytes.data(), threadEpNewBytes.size(), 0));

			uint64_t hThread64;
			CheckStatus(X64Syscall(NtCreateThreadEx64, &hThread64, THREAD_ALL_ACCESS, NULL, hProcess, allocatedAddress, NULL, FALSE, NULL, NULL, NULL, NULL));
			HandleGuard injectedThreadGuard((HANDLE)(INT_PTR)hThread64, CloseHandle);
		}
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
