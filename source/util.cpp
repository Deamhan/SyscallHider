#include "util.hpp"

#include <Windows.h>

bool EnableVTMode() noexcept
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode))
		return false;

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	return SetConsoleMode(hOut, dwMode);
}
