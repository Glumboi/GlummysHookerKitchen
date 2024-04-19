# Import the necessary Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import java.io.PrintWriter as PrintWriter
import threading

# Initialize the decompiler interface
ifc = DecompInterface()
ifc.openProgram(currentProgram)

saved_sigs_count = 0

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

# Function to process a single function
def process_function(export, function):
    results = ifc.decompileFunction(function, 5, ConsoleTaskMonitor())
    if results.decompileCompleted():
        decomp_func = results.getDecompiledFunction()
        decomp_func_sig = decomp_func.getSignature()
        print("[+] Checking function " + decomp_func_sig + " against the export: " + export)
        if export in decomp_func_sig:
            # Write the function signature to the file
            with threading.Lock():
                pw.println(decomp_func.getSignature())
            return 1
    return 0

# Function to process functions in parallel
def process_functions_in_parallel(export):
    global saved_sigs_count
    for function in functionManager.getFunctions(True):
        saved_sigs_count += process_function(export, function)

# Create threads to process exports in parallel
threads = []
for export in exports:
    thread = threading.Thread(target=process_functions_in_parallel, args=(export,))
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Close the PrintWriter
pw.close()
print("[+] Saved a total of " + str(saved_sigs_count) + " function signatures!")
