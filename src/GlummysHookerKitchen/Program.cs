using System.Text;
using System.Windows.Forms;
using PeNet;

namespace GlummysHookerKitchen;

class Program
{
    private static KitchenSettings settings = new KitchenSettings("KitchenConfig.ini");
    private static string target = string.Empty;
    private static char quote = '\"';

    [STAThread]
    static void Main(string[] args)
    {
        if (settings.GhidraPath == "UNDEFINED" || string.IsNullOrEmpty(settings.GhidraPath))
        {
            Console.WriteLine("No ghidra path found in the config, please select your ghidra location!");
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.InitialDirectory = Directory.GetCurrentDirectory();
                fbd.Description = "Please select your ghidra location!";
                DialogResult result = fbd.ShowDialog();
                if (result == DialogResult.OK && !string.IsNullOrWhiteSpace(fbd.SelectedPath))
                {
                    settings.GhidraPath = fbd.SelectedPath;
                }
                else
                {
                    Console.WriteLine("The config wasn't set up properly, aborting...");
                    Thread.Sleep(5000);
                    Environment.Exit(0);
                }
            }
        }

        Console.WriteLine("Enter target compiled file: ");
        target = Console.ReadLine() ?? string.Empty;
        target = target.Replace("\"", ""); //Normalize path

        if (string.IsNullOrEmpty(target) || !File.Exists(target))
        {
            Console.WriteLine("No file entered, aborting...");
            Thread.Sleep(5000);
            Environment.Exit(0);
        }

        PeFile peFile = new PeFile(target); //Load target
        List<string> exports = new();
        foreach (var export in peFile.ExportedFunctions)
        {
            exports.Add(export.Name);
        }

        Console.WriteLine(
            "If you have already dumped all export sigs, you can now enter '1' to parse it into C++ source files" +
            " (enter 0 or anything other than 1 to dump from the target):");

        short.TryParse(Console.ReadLine(), out var choice);

        if (choice == 1)
        {
            ParseDump(target, exports);
        }
        else
        {
            DumpTarget(target, exports);
        }

        Console.WriteLine("Press any button to exit...");
        Console.ReadKey();
    }

    static void ParseDump(string target, List<string> exports)
    {
        Console.WriteLine("Please select the text file containing the exported sigs!");

        string sigFile = string.Empty;
        using (OpenFileDialog dlg = new OpenFileDialog())
        {
            dlg.InitialDirectory = Directory.GetCurrentDirectory();
            dlg.Filter = "txt files (*.tx)|*.txt|All files (*.*)|*.*";
            dlg.FilterIndex = 2;
            dlg.Title = "Select sig file...";

            if (dlg.ShowDialog() == DialogResult.OK)
            {
                sigFile = dlg.FileName;
            }
        }

        Console.WriteLine("Getting functions...");

        List<CPPFunction> functions = new();
        foreach (var sig in File.ReadLines(sigFile))
        {
            //TODO: Fix duplication bug in the python script, instead of here!
            CPPFunction fn = new CPPFunction(sig);
            bool alreadyDefined = false;
            foreach (var fn2 in functions)
            {
                alreadyDefined = fn2.Name == fn.Name;
            }

            if (alreadyDefined) continue;

            Console.WriteLine("==== CPP FUNCTION ====");
            functions.Add(fn);
            fn.PrintInfo();
            Console.WriteLine("======================");
        }

        string headerFileBase = @"#pragma once

#include <Windows.h>
#include <Minhook.h>
#include <cstdint>
#include <iostream>
#include <stdio.h>

#define MAKE_HOOK(original, hook)\
{\
	MH_CreateHook(original, &hook, reinterpret_cast<LPVOID*>(&original)); \
}

#define CONSOLE_TITLE ""Hooks-Console""

#define DEBUG_TO_CONSOLE(msg) \
{ \
    std::cout << msg; \
}

#define TOPSEPERATOR ""================================================\n""
#define BOTTOMSEPERATOR ""\n================================================\n""

#pragma region Helpers

template<typename targetType>
inline static void AssignAddressToOriginalUsingModule(
	targetType& target,
	const char* targetName,
	HMODULE hModule)
{
	if (hModule != nullptr)
	{
		FARPROC targetAddress = GetProcAddress(hModule, targetName);
		if (targetAddress != nullptr)
		{
			target = reinterpret_cast<targetType>(targetAddress);
		}
		else
		{
			return;
		}
	}
	else
	{
		return;
	}
}

#pragma endregion

#pragma region Hooks

";
        StringBuilder headerBuilder = new StringBuilder(headerFileBase);
        foreach (var fn in functions)
        {
            headerBuilder.Append(fn.GetFullHook() + "\n\n");
        }

        headerBuilder.Append(@$"

#pragma endregion

void InitHooks()
{{

    //Allocate console
    if (AllocConsole())
    {{
	    SetConsoleTitleA(CONSOLE_TITLE);
	    FILE* f;
	    FILE* f2;
	    freopen_s(&f, ""conout$"", ""w"", stdout);
	    freopen_s(&f2, ""conout$"", ""w"", stderr);
    }}

    MH_STATUS minhookEnableStat = MH_Initialize();
    if (minhookEnableStat == MH_OK)
    {{
        HMODULE targetModule = GetModuleHandleA(""{Path.GetFileName(target)}"");

");

        foreach (var fn in functions)
        {
            headerBuilder.Append(@$"
        AssignAddressToOriginalUsingModule(
	    {fn.Name}_o,
	    ""{fn.Name}"",
	    targetModule);
        MAKE_HOOK({fn.Name}_o, {fn.Name}_hook);

");
        }

        headerBuilder.Append(@"
	    MH_STATUS enableStat = MH_EnableHook(MH_ALL_HOOKS);
	    if (enableStat != MH_OK) {} //Handle errors
    }
}");
        string headerFilePath = "Hooks.h";
        File.WriteAllText(headerFilePath, headerBuilder.ToString());
        Console.WriteLine("Wrote all hooks to the file: " + headerFilePath);
    }

    static void DumpTarget(string target, List<string> exports)
    {
        File.WriteAllLines("targets_exports.txt", exports);

        Console.WriteLine($"Created targets_exports.txt file for {target}.");
        Console.WriteLine("Creating runner.bat");
        string batch = @$"@echo off
set ghidra_path=""{settings.GhidraPath}""
set script_path=./sigDump_AllSigs_WithExpCheck.py 
set input_file=""{target}""

REM Get the current timestamp
for /f ""tokens=2 delims=="" %%a in ('wmic OS Get localdatetime /value') do set ""dt=%%a""
set ""dt=%dt:~0,8%-%dt:~8,6%""

REM Run Ghidra in headless mode, analyze the input file, and run the script
%ghidra_path%\support\analyzeHeadless . TempProject_%dt% -import %input_file% -postScript %script_path%

REM Add a pause at the end
pause";
        File.WriteAllText("runner.bat", batch);
        Console.WriteLine("Created runner.bat!");
    }
}