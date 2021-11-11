#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <utility>

#include "cmdline.hpp"
#include "parser.hpp"
#include "util.hpp"

static CmdLineOptionValue gExec = {}, gDll = {}, gFunc = {};

static const std::vector<CmdLineOption> gCmdLineOptions
{
	{ 'e', "Exec",     "Exec file to run and inject",       "", true, gExec},
	{ 'd', "DLL",      "DLL payload",                       "", true, gDll  },
	{ 'f', "Function", "Function from payload DLL to call", "", true, gFunc },
};

int main(int argc, const char** argv)
{
	try
	{
		if (!EnableVTMode())
			throw std::exception("Unable to prepare terminal\n");

		ParseCmdLine(gCmdLineOptions, argc, argv);

		auto ntdll = ParseNtdll();
		auto NtSetInformationThread64 = GET_SYSCALL_PTR(ntdll, NtSetInformationThread);
		auto NtQueryInformationThread64 = GET_SYSCALL_PTR(ntdll, NtQueryInformationThread);
		auto NtAllocateVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtAllocateVirtualMemory);
		auto NtWriteVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtWriteVirtualMemory);
		auto NtReadVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtReadVirtualMemory);
		auto NtQueryVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtQueryVirtualMemory);
		auto NtProtectVirtualMemory64 = GET_SYSCALL_PTR(ntdll, NtProtectVirtualMemory);

		STARTUPINFOA sa = { sizeof(sa) };
		PROCESS_INFORMATION pi = {};
		std::unique_ptr<char[], void(*)(void*)> pathCopy(strdup(gExec.first.c_str()), free);
		auto res = CreateProcessA(nullptr, pathCopy.get(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &sa, &pi);
		if (!res)
			throw std::system_error(GetLastError(), std::system_category(),
				std::string("unable to run target process \'").append(pathCopy.get()).append("\'"));

		std::unique_ptr<PROCESS_INFORMATION, void(*)(PROCESS_INFORMATION*)> processInfoGuard(&pi, [](PROCESS_INFORMATION* pi) 
			{
				CloseHandle(pi->hProcess);
				CloseHandle(pi->hThread);
			});

		auto ep = GetExeEntryPoint(NtQueryVirtualMemory64, NtReadVirtualMemory64, (uint64_t)pi.hProcess);

		uint8_t injectedCode[] = {
			0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
			0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
			0xFF, 0xD0,                   // call eax
			0x05, 0x78, 0x56, 0x34, 0x12, // add eax, 0x12345678
			0xFF, 0xD0,                   // call eax
			0xC3                          // ret
		};
		uint64_t stringSizeInBytes = strlen(argv[2]) + 1;
		std::vector<uint8_t> epNewBytes(sizeof(injectedCode) + stringSizeInBytes);
		*(uint32_t*)(injectedCode + 1) = (uint32_t)ep + sizeof(injectedCode);
		auto funcPtr = GetProcAddress(GetModuleHandleA("kernelbase"), "LoadLibraryA");
		*(uint32_t*)(injectedCode + 6) = (uint32_t)funcPtr;

		auto hModule = LoadLibraryExA(gDll.first.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
		if (hModule == nullptr)
			throw std::system_error(GetLastError(), std::system_category(),
				std::string("unable to load module \'").append(gDll.first).append("\'"));

		auto funcToRun = GetProcAddress(hModule, gFunc.first.c_str());
		if (funcToRun == nullptr)
			throw std::logic_error(gDll.first + "!" + gFunc.first + "does not exist");

		*(uint32_t*)injectedCode = ((uint32_t)funcToRun - (uint32_t)hModule);

		memcpy(epNewBytes.data(), injectedCode, sizeof(injectedCode));
		memcpy(epNewBytes.data() + sizeof(injectedCode), argv[2], stringSizeInBytes);

		uint64_t addressToVProt = ep;
		uint64_t sizeToVProt = epNewBytes.size();
		uint64_t oldVProt = 0;
		auto status = X64Syscall(NtProtectVirtualMemory64, pi.hProcess, &addressToVProt, &sizeToVProt, PAGE_EXECUTE_READWRITE, &oldVProt);
		status = X64Syscall(NtWriteVirtualMemory64, pi.hProcess, ep, epNewBytes.data(), epNewBytes.size(), 0);

		ResumeThread(pi.hThread);
	}
	catch (const std::exception& ex)
	{
		printf("\x1b[91mError: %s\n\x1b[m", ex.what());
		return 1;
	}

	return 0;
}
