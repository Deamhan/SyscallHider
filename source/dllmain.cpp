#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)   // reserved
{
	return TRUE;		
}

extern "C" __declspec(dllexport) void Handler()
{
	while(true)
		MessageBoxA(nullptr, "Message", "Text", MB_OK);
}
