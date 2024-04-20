using System.Text;
using PeNet;
using PeNet.Header.Pe;

namespace GlummysHookerKitchen;

//https://github.com/Flangvik/SharpDllProxy

public class SharpDll_Mod
{
    private static string dllTemplate = @"
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#include ""hooks.h""

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

PRAGMA_COMMENTS

DWORD WINAPI DoMagic()
{
	InitHooks();
	return 0;
}

    BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD ul_reason_for_call,
        LPVOID lpReserved
    )
    {
        HANDLE threadHandle;

        switch (ul_reason_for_call)
        {
            case DLL_PROCESS_ATTACH: 
                threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DoMagic, NULL, 0, NULL);
                CloseHandle(threadHandle);
            case DLL_THREAD_ATTACH:
                break;
            case DLL_THREAD_DETACH:
                break;
            case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
    }
";

    public static string ProcessTarget(string target)
    {
        ExportFunction[] exports = new PeFile(target).ExportedFunctions ?? Array.Empty<ExportFunction>();
        StringBuilder pragmaBuilder = new StringBuilder();
        string proxyOg = Path.GetFileName(target).Split('.').First() + "_O";

        for (int i = 0; i < exports.Length; i++)
        {
            var exportedFunc = exports[i];
            pragmaBuilder.Append(
                $"#pragma comment(linker, \"/export:{exportedFunc.Name}={proxyOg}.{exportedFunc.Name},@{exportedFunc.Ordinal}\")\n");
        }

        return dllTemplate.Replace("PRAGMA_COMMENTS", pragmaBuilder.ToString());
        //Example usage of return result
        //File.WriteAllText("dllmain.cpp", ProcessTarget(target, exps));
    }
}