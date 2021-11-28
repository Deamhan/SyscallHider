#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <climits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <windows.h>

typedef std::unique_ptr<uint8_t[], void(*)(void*)> exec_ptr_t;
typedef std::map<std::string, uint32_t> syscall_map;

std::pair<exec_ptr_t, syscall_map> ParseNtdll();

#if !_X64_
extern "C" NTSTATUS X64Function(uint64_t Func, uint32_t Argc, uint64_t Arg0, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, ...);
#endif // _X64_

template <class Func, class... Args>
NTSTATUS X64Syscall(Func func, Args... args)
{
#if _X64_
	return func((uint64_t)args...);
#else
	return X64Function((uint64_t)func, sizeof...(args), (uint64_t)args...);
#endif // _X64_
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((int)(status) >= 0)
#endif // NT_SUCCESS

template <class Func>
inline Func GetSyscallPtr(const exec_ptr_t& blob, const syscall_map& dict, const char * name)
{
	try
	{
		return (Func)(blob.get() + dict.at(name));
	}
	catch (const std::out_of_range&)
	{
		throw std::exception(std::string("unable to locate function: ").append(name).c_str());
	}
}

#define GET_SYSCALL_PTR(dll, name) GetSyscallPtr<name##64_t>(dll.first, dll.second, #name)

class BufferSafeAccessor
{
	const std::vector<uint8_t>& mBuffer;
	size_t mPosition;
public:
	BufferSafeAccessor(const std::vector<uint8_t>& buffer) : mBuffer(buffer), mPosition(0) {}

	template <class T>
	const T* GetPointer(size_t count = 1)
	{
		const auto startPosition = mPosition;
		mPosition += sizeof(T) * count;
		if (mBuffer.size() < mPosition)
		{
			mPosition = startPosition;
			throw std::out_of_range("buffer is not long enough");
		}

		return (const T*)(&mBuffer[startPosition]);
	}

	std::string_view GetString()
	{
		const size_t startPosition = mPosition;
		for (; mPosition < mBuffer.size(); ++mPosition)
		{
			if (mBuffer[mPosition] == 0)
				return std::string_view((const char*)&mBuffer[startPosition], mPosition - startPosition);
		}

		mPosition = startPosition;
		throw std::out_of_range("unable to find string end");
	}

	BufferSafeAccessor& Seek(size_t position)
	{
		if (position > mBuffer.size())
			throw std::out_of_range("buffer is not long enough");

		mPosition = position;
		return *this;
	}
};

namespace fs = std::filesystem;

class IFilter
{
	virtual bool Filter(std::string_view) = 0;
public:
    bool operator()(std::string_view name) { return Filter(name); }
};

enum class CPUArch
{
	Unknown = 0,
	X86 = IMAGE_FILE_MACHINE_I386,
	X64 = IMAGE_FILE_MACHINE_AMD64
};

template <bool isMappedImage>
syscall_map ParseDllExport(BufferSafeAccessor buffer, IFilter& filter, bool getExportByRVA, CPUArch expectedArch);

template <bool isMappedImage>
syscall_map ParseDllExport(const fs::path& path, IFilter& filter, bool getExportByRVA, CPUArch expectedArch);

fs::path GetDllPath(std::string_view name, bool isWOW64);

class Wow64RedirectionDisabler
{
#ifndef _X64_
	PVOID mOldValue;
	BOOL  mOk;
public:
	Wow64RedirectionDisabler() noexcept
	{
		mOk = Wow64DisableWow64FsRedirection(&mOldValue);
	}

	~Wow64RedirectionDisabler()
	{
		if (mOk)
			Wow64RevertWow64FsRedirection(mOldValue);
	}
#endif
};
