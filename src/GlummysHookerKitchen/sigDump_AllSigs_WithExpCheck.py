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

# Set to keep track of encountered signatures
encountered_sigs = set()

# Get the current program
program = currentProgram

# Get the function manager
functionManager = program.getFunctionManager()

# Iterate over all the functions in the current program
for function in functionManager.getFunctions(True):
    results = ifc.decompileFunction(function, 5, ConsoleTaskMonitor())
    if results.decompileCompleted():
        decomp_func = results.getDecompiledFunction()
        decomp_func_sig = decomp_func.getSignature()
        # Check if the signature has already been encountered
        print("[+] saving sig: " + decomp_func_sig)
        pw.println(decomp_func_sig);
        saved_sigs_count += 1

# Close the PrintWriter
pw.close()
print("[+] Saved a total of " + str(saved_sigs_count) + " function signatures!")

print("[+] Checking exports against saved sigs...")

# Check the saved sigs against the exports
exported_sigs = []
for saved_sig in open(output_file).readlines():
    for export in exports:
        print("[+] Checking sig " + saved_sig.strip() + " against the export: " + export.strip())
        if export.strip() in saved_sig.strip():
            exported_sigs.append(saved_sig.strip() + '\n')

# Remove duplicates
stripped_exported_sigs = []
for i in exported_sigs:
    if i not in stripped_exported_sigs:
        stripped_exported_sigs.append(i)
        continue
    print("[+] Excluding duplicate: " + i)

with open(operating_filename.replace('.', '_') + '_' + output_file, 'w') as filetowrite:
    filetowrite.write(''.join(stripped_exported_sigs))

print("[+] Finished saving signatures!")
