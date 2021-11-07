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
	typedef NTSTATUS(NTAPI* Func_t)(Args...);
	return ((Func_t)func)(args...);
#else
	return X64Function((uint64_t)func, sizeof...(args), (uint64_t)args...);
#endif // _X64_
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((int)(status) >= 0)
#endif // NT_SUCCESS

#define GET_SYSCALL_PTR(dll, Name) (Name##64_t)(dll.first.get() + dll.second[#Name])
