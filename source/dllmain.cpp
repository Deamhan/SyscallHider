#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)   // reserved
{
	return TRUE;		
}

extern "C" __declspec(dllexport) void Handler(const char * text)
{
	while(true)
		MessageBoxA(nullptr, text, "Text", MB_OK);
}

extern "C" __declspec(dllexport) const char* Arg()
{
	return "whatever";
}
