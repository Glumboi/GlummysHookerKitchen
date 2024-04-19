# Import the necessary Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import java.io.PrintWriter as PrintWriter
import os

# Initialize the decompiler interface
ifc = DecompInterface()
ifc.openProgram(currentProgram)

saved_sigs_count = 0
operating_filename = os.path.basename(currentProgram.getExecutablePath())

exports = []
with open("targets_exports.txt") as targets_file:
    exports = targets_file.readlines()

# Create a PrintWriter to write the output to a file
output_file = "function_signatures.txt"
pw = PrintWriter(output_file)

# Get the current program
program = currentProgram

# Get the function manager
functionManager = program.getFunctionManager()

# Iterate over all the functions in the current program
for function in functionManager.getFunctions(True):
    results = ifc.decompileFunction(function, 5, ConsoleTaskMonitor())
    if results.decompileCompleted():
        decomp_func = results.getDecompiledFunction()
        decomp_func_sig = decomp_func.getSignature();
        print("[+] saving sig: " + decomp_func_sig)
        pw.println(decomp_func_sig)
        saved_sigs_count += 1

# Close the PrintWriters
pw.close()
print("[+] Saved a total of " + str(saved_sigs_count) + " function signatures!")

# Reset sig count to use in later code
saved_sigs_count = 0

print("[+] Checking exports against saved sigs...")

# Check the saved sigs against the exports
exported_sigs = []
found_all_exports = False
for saved_sig in open(output_file).readlines():
    if found_all_exports:
        break
    for export in exports:
        print("[+] Checking sig " + saved_sig.strip() + " against the export: " + export.strip())
        if export.strip() in saved_sig.strip():
            exported_sigs.append(saved_sig.strip() + '\n')
            saved_sigs_count += 1
            if saved_sigs_count >= len(exports):
                found_all_exports = True
                break

with open(operating_filename.replace('.', '_') + '_' + output_file, 'w') as filetowrite:
    filetowrite.write(''.join(exported_sigs))

print("[+] Finished saving signatures!")
