# GlummysHookerKitchen 
 Auto export hooks creator, make your hooker life easier!

A small CLI based application that will setup a ghidra headless batch runner to dump and convert exported functions of a dll (maybe even executables, didn't test that) into hooks!


# Requirements for using GlummysHookerKitchen
* .NET 8.0 Runtime

* A Windows version that supports .NET 8.0 

* Python 3.? (not sure exactly which, but I have 3.8 and 3.11 installed in my system)

* Ghidra 11.X 

* VCPKG

* The following VCPKG packages:<br/>
Minhook ```vcpkg install minhook:x64-windows-static```<br/>

* (not required but recommended) My "GlummysFishingRod" to inject an inject-able dll

# Dumping exported functions (simple explanation)

* Launch "GlummysHookerKitchen.exe", first launch will tell you right away to select your ghidra root path
* Enter the path to the target file
* Enter nothing on the next prompt 
* Wait til the runner.bat file has been created
* Close "GlummysHookerKitchen.exe", open a cmd or terminal in the runner.bat file location and run it
* wait til it's done 
* You successfully dumped all exported functions!

# Using dumped functions to create a hooks.h header file to use in an inject-able DLL

* Launch "GlummysHookerKitchen.exe"
* Enter the path to the target file
* Enter '1' to enter the parse sigs mode on the current target
* Select the text file containing the dumped exported signatures of the target (example: File_dll_function_signatures.txt)
* Wait for the process to finish
* Locate the created hooks.h file and include it in your project
* Initialize hooks like this: 
```C++ 
// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "hooks.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)InitHooks, nullptr, 0, nullptr);
	}
	return TRUE;
}
``` 

# This is it for now, thank you for reading til here!
