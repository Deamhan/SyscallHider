#include "util.hpp"

#include <array>
#include <cinttypes>
#include <string>
#include <tuple>
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

template <class OptHeader>
inline uint64_t GetImageSize(BufferSafeAccessor& accessor)
{
	auto optHeader = accessor.GetPointer<OptHeader>();
	return optHeader->SizeOfImage;
}

static std::tuple<uint64_t, bool, bool> ProcessImage(
	uint64_t address,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	std::vector<uint8_t> buffer(0x1000);
	auto status = X64Syscall(NtReadVirtualMemory, processHandle, address, buffer.data(), buffer.size(), 0);
	if (!NT_SUCCESS(status))
		return { 0, false, false };

	try
	{
		BufferSafeAccessor accessor(buffer);
		auto dos = accessor.GetPointer<IMAGE_DOS_HEADER>();
		if (dos->e_magic != 0x5a4d)
			return { 0, false, false };

		auto signature = accessor.Seek(dos->e_lfanew).GetPointer<uint32_t>();
		if (*signature != 0x4550)
			return { 0, false, false };

		auto fileHeader = accessor.GetPointer<IMAGE_FILE_HEADER>();
		if ((fileHeader->Characteristics & IMAGE_FILE_DLL) != 0)
		{
			uint32_t imageSize = 0;
			bool isAMD64 = false;
			switch (fileHeader->Machine)
			{
			case IMAGE_FILE_MACHINE_I386:
				imageSize = GetImageSize<IMAGE_OPTIONAL_HEADER32>(accessor);
				break;
			case IMAGE_FILE_MACHINE_AMD64:
				imageSize = GetImageSize<IMAGE_OPTIONAL_HEADER64>(accessor);
				isAMD64 = true;
				break;
			default:
				return { 0, false, true };
			}

			buffer.resize(imageSize);
			status = X64Syscall(NtReadVirtualMemory, processHandle, address, buffer.data(), buffer.size(), 0);
			if (!NT_SUCCESS(status))
				return { 0, isAMD64, true };

			class SyscallFilter : public IFilter
			{
				bool Filter(std::string_view name) override
				{
					return (name == "LdrLoadDll");
				}
			} filter;
			auto exports = ParseDllExport<true>(buffer, filter, true);
			if (exports.empty())
				return { 0, isAMD64, true };

			return { exports.begin()->second + address, isAMD64, true };
		}

		switch (fileHeader->Machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			return { GetEntryPoint<IMAGE_OPTIONAL_HEADER32>(accessor, address), false, false };
		case IMAGE_FILE_MACHINE_AMD64:
			return { GetEntryPoint<IMAGE_OPTIONAL_HEADER64>(accessor, address), true, false };
		default:
			return { 0, false, false };
		}
	}
	catch (const std::out_of_range&)
	{
		return { 0, false, false };
	}
}

const uint32_t PAGE_SIZE = 4096;

inline uint64_t& GetReqLdr(uint64_t pLdrLoadDll[2], bool isAMD64)
{
	return pLdrLoadDll[isAMD64 ? 0 : 1];
}

inline bool IsEnoughData(uint64_t ep, uint64_t pLdrLoadDll[2], bool isAMD64)
{
	return (ep != 0 && GetReqLdr(pLdrLoadDll, isAMD64) != 0);
}

std::tuple<uint64_t, uint64_t, bool> GetProcessInfo(
	NtQueryVirtualMemory64_t NtQueryVirtualMemory,
	NtReadVirtualMemory64_t NtReadVirtualMemory,
	uint64_t processHandle)
{
	uint64_t size = PAGE_SIZE;
	MEMORY_BASIC_INFORMATION64 mbi;

	uint64_t pLdrLoadDll[2] = {};
	uint64_t ep = 0;

	uint64_t prevModuleBase = 0;
	for (uint64_t address = 0; NT_SUCCESS(X64Syscall(NtQueryVirtualMemory, processHandle, address, 0, &mbi, sizeof(mbi), 0)); address += size)
	{
		size = std::max<uint64_t>(PAGE_SIZE, mbi.RegionSize);
		if (mbi.Type != MEM_IMAGE || mbi.AllocationBase == prevModuleBase)
			continue;

		prevModuleBase = mbi.AllocationBase;
		auto [addr, isAMD64, isNtdll] = ProcessImage(mbi.AllocationBase, NtReadVirtualMemory, processHandle);
		if (addr != 0)
		{
			if (isNtdll)
				GetReqLdr(pLdrLoadDll, isAMD64) = addr;
			else
				ep = addr;
		}

		if (IsEnoughData(ep, pLdrLoadDll, isAMD64))
			return { ep, GetReqLdr(pLdrLoadDll, isAMD64), isAMD64 };
	}

	return { 0, 0, false };
}

static const uint8_t injectedCode64[] = {
	0x48, 0x89, 0xE5,                                           // mov  rbp, rsp
	0x48, 0x83, 0xE4, 0xF0,                                     // mov  rsp, 0xfffffffffffffff0
	0x48, 0x83, 0xEC, 0x20,                                     // sub  rsp, 0x20
	0x48, 0x31, 0xC9,                                           // xor  rcx, rcx
	0x48, 0x31, 0xD2,                                           // xor  rdx, rdx
	0x49, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov  r8,  0x1234567890abcdef (PUNICODE_STRING)
	0x48, 0xBB, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov  rbx, 0x1234567890abcdef (PHMODULE)
	0x49, 0x89, 0xD9,                                           // mov  r9,  rbx
	0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov  rax, 0x1234567890abcdef (pLdrLoadDll)
	0xFF, 0xD0,                                                 // call rax
	0x48, 0x8B, 0x03,                                           // mov  rax, [rbx]
	0x48, 0x05, 0x78, 0x56, 0x34, 0x12,                         // add  rax, 0x12345678         (Exported function RVA)
	0xFF, 0xD0,                                                 // call rax
	0x48, 0x89, 0xEC,                                           // mov  rsp, rbp
	0xC3                                                        // ret
};

static const uint8_t injectedCode32[] = {
	0x89, 0xE5,                   // mov  ebp, esp
	0xBB, 0x78, 0x56, 0x34, 0x12, // mov  ebx, 0x12345678 (PHMODULE)
    0x53,                         // push ebx 
	0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678      (PUNICODE_STRING)
	0x31, 0xC0,                   // xor  eax, eax
	0x50,                         // push eax
	0x50,                         // push eax    
	0xB8, 0x78, 0x56, 0x34, 0x12, // mov  eax, 0x12345678 (pLdrLoadDll)
	0xFF, 0xD0,                   // call eax
	0x8B, 0x03,                   // mov  eax, [ebx]
	0x05, 0x78, 0x56, 0x34, 0x12, // add  eax, 0x12345678 (Exported function RVA)
	0xFF, 0xD0,                   // call eax
	0x89, 0xEC,                   // mov  esp, ebp
	0xC3                          // ret
};

#pragma pack (push, 4)
struct UNICODE_STRING32 {
	USHORT   Length;
	USHORT   MaximumLength;
	uint32_t Buffer;
};
#pragma pack(pop)

#pragma pack (push, 8)
struct UNICODE_STRING64 {
	USHORT   Length;
	USHORT   MaximumLength;
	uint64_t Buffer;
};
#pragma pack(pop)

template <bool isAMD64>
struct arch_traits_t
{
	static const size_t unicodeStringOffset = 19;
	static const size_t hmodudeOffset = 29;
	static const size_t ldrLoadDllOffset = 42;
	static const size_t exportedFuncRVAOffset = 57;

	static constexpr auto GetInjectedCode()
	{
		return std::pair<const uint8_t*, size_t>(injectedCode64, sizeof(injectedCode64));
	}

	typedef uint64_t ptr_t;
	typedef UNICODE_STRING64 unicode_str_t;
};

template <>
struct arch_traits_t<false>
{
	static const size_t unicodeStringOffset = 9;
	static const size_t hmodudeOffset = 3;
	static const size_t ldrLoadDllOffset = 18;
	static const size_t exportedFuncRVAOffset = 27;

	static constexpr auto GetInjectedCode()
	{
		return std::pair<const uint8_t*, size_t>(injectedCode32, sizeof(injectedCode32));
	}

	typedef uint32_t ptr_t;
	typedef UNICODE_STRING32 unicode_str_t;
};

template <bool isAMD64>
static std::vector<uint8_t> GetCodeBuffer(const std::string& dllPath, const std::string& funcName, uint64_t ep, uint64_t pLdrLoadDll)
{
	typedef typename arch_traits_t<isAMD64>::ptr_t ptr_t;
	typedef typename arch_traits_t<isAMD64>::unicode_str_t unicode_str_t;

	std::wstring wDllPath(dllPath.begin(), dllPath.end());
	size_t wPathPureLenInBytes = wDllPath.length() * sizeof(wchar_t);

	auto [codeBuffer, codeSize] = arch_traits_t<isAMD64>::GetInjectedCode();
	size_t usOffset = codeSize + sizeof(ptr_t);
	size_t strBufferOffset = usOffset + sizeof(unicode_str_t);
	unicode_str_t us = { (USHORT)wPathPureLenInBytes, (USHORT)wPathPureLenInBytes, (ptr_t)(ep + strBufferOffset) };
	size_t wPathTotalLenInBytes = wPathPureLenInBytes + sizeof(wchar_t);

	/*
	 * Layout:
	 *     code block
	 *     HMODULE
	 *     UNICOSE_STRING
	 *     Unicode string buffer
	 */
	std::vector<uint8_t> epNewBytes(strBufferOffset + wPathTotalLenInBytes, 0);
	memcpy(epNewBytes.data(), codeBuffer, codeSize);
	memcpy(epNewBytes.data() + usOffset, &us, sizeof(us));
	memcpy(epNewBytes.data() + strBufferOffset, wDllPath.c_str(), wPathTotalLenInBytes);

	*(ptr_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::unicodeStringOffset) = ep + usOffset;
	*(ptr_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::hmodudeOffset) = ep + codeSize;
	*(ptr_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::ldrLoadDllOffset) = pLdrLoadDll;

	class SyscallFilter : public IFilter
	{
		bool Filter(std::string_view name) override
		{
			return (name == "Handler");
		}
	} filter;
	auto exports = ParseDllExport<false>(dllPath, filter, true);
	if (exports.empty())
		throw std::logic_error(dllPath + "!" + funcName + " does not exist");

	*(uint32_t*)(epNewBytes.data() + arch_traits_t<isAMD64>::exportedFuncRVAOffset) = exports.begin()->second;

	return epNewBytes;
}

std::vector<uint8_t> GetCodeBuffer(bool isAMD64, const std::string& dllPath, const std::string& funcName, uint64_t ep, uint64_t pLdrLoadDll)
{
	if (isAMD64)
		return GetCodeBuffer<true>(dllPath, funcName, ep, pLdrLoadDll);

	return GetCodeBuffer<false>(dllPath, funcName, ep, pLdrLoadDll);
}

RtlNtStatusToDosError_t RtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(GetModuleHandleA("ntdll"), "RtlNtStatusToDosError");
