import time
import os
import shutil
import hashlib
import traceback
import urllib.request
from pathlib import Path
import pyghidra

class Analyzer():
    def __init__(self, projectFolder: Path, projectName: str, inputPath: Path, localSymbolPath: Path = Path("./symbols"), symbolServer: str = "https://msdl.microsoft.com/download/symbols"):
        self.filePaths        = []
        
        # Configure Symbol Resolution
        self.localSymbolPath  = localSymbolPath
        self.symbolServer     = symbolServer
        
        # Ensure the local symbol cache directory actually exists
        self.localSymbolPath.mkdir(parents=True, exist_ok=True)
        
        # Resolve the paths given by the user
        self.resolveInputPath(inputPath=inputPath)
        
        # Set the environment variable so Ghidra knows where to look
        os.environ["_NT_SYMBOL_PATH"] = f"SRV*{self.localSymbolPath.resolve()}*{self.symbolServer}"
            
        self.ghidraAnalyzeObj = ghidraAnalyzer(
            projectFolder=projectFolder,
            projectName=projectName,
            filePaths=self.filePaths
        )
        
    def get_symbols(self):
        print("\n--- Resolving Symbols ---")
        for filePath, hashName in self.filePaths:
            self.fetch_symbol(filePath)
            
    def fetch_symbol(self, file_path: Path):
        """
        Parses the PE debug header from raw bytes to ensure the PDB is placed in 
        the strict Microsoft SymSrv format: Symbol_Name / GUID+Age / Symbol_Name.
        """
        try:
            import pefile
            import struct
        except ImportError:
            print("[!] 'pefile' module not found. Skipping explicit Python symbol routing.")
            return

        try:
            pe = pefile.PE(str(file_path.resolve()))
            if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                return

            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                if dbg.struct.Type == 2: # IMAGE_DEBUG_TYPE_CODEVIEW
                    raw_data = pe.get_data(dbg.struct.AddressOfRawData, dbg.struct.SizeOfData)
                    
                    if not raw_data.startswith(b'RSDS') or len(raw_data) < 24:
                        continue
                        
                    data1, data2, data3 = struct.unpack('<IHH', raw_data[4:12])
                    data4 = raw_data[12:20]
                    age = struct.unpack('<I', raw_data[20:24])[0]
                    
                    pdb_name_bytes = raw_data[24:].split(b'\x00')[0]
                    pdb_name = pdb_name_bytes.decode('utf-8', errors='ignore').split('\\')[-1]
                    
                    guid4_str = "".join([f"{b:02X}" for b in data4])
                    guid_age_str = f"{data1:08X}{data2:04X}{data3:04X}{guid4_str}{age:X}"
                    
                    sym_dir  = self.localSymbolPath / pdb_name / guid_age_str
                    sym_path = sym_dir / pdb_name
                    
                    if sym_path.exists():
                        print(f"[*] Symbol already cached at: {sym_path}")
                        return
                        
                    sym_dir.mkdir(parents=True, exist_ok=True)

                    local_pdb = file_path.with_suffix('.pdb')
                    if local_pdb.exists():
                        print(f"[*] Found adjacent local symbol file: {local_pdb.name}")
                        shutil.copy2(local_pdb, sym_path)
                        return

                    url = f"{self.symbolServer.rstrip('/')}/{pdb_name}/{guid_age_str}/{pdb_name}"
                    print(f"[*] Downloading PDB from Microsoft: {url}")
                    
                    req = urllib.request.Request(url, headers={'User-Agent': 'Microsoft-Symbol-Server/10.0.10036.0'})
                    with urllib.request.urlopen(req) as response, open(sym_path, 'wb') as out_file:
                        shutil.copyfileobj(response, out_file)
                        
                    print(f"[*] Successfully saved symbol to cache: {sym_path}")
                    return

        except Exception as e:
            print(f"[!] Failed to manually fetch or route symbol: {e}")

    def simplifyPaths(self):
        validExtensions = ['.exe', '.dll', '.sys', '.so']
        newPathList = []
        for path in self.filePaths:
            if path.suffix.lower() in validExtensions:
                newPathList.append((path, f"{path.name}--{hashlib.sha256(path.resolve().read_bytes()).hexdigest()}"))
                
        self.filePaths = newPathList
        
    def resolveInputPath(self, inputPath: Path):
        self.filePaths = []
        if inputPath.is_file():
            self.filePaths = [inputPath]
        elif inputPath.is_dir():
            for path in inputPath.rglob("*"):
                if path.is_file():
                    self.filePaths.append(path)
                    
        self.simplifyPaths()

class ghidraAnalyzer():
    def __init__(self, projectFolder: Path, projectName: str, filePaths: list):
        self.projectFolder    = projectFolder
        self.projectName      = projectName
        self.filePaths        = filePaths
        
        self.projectFolder.mkdir(parents=True, exist_ok=True)
        pyghidra.start()
        
    def analyze(self):
        for original_path, hashed_name in self.filePaths:
            self.fileAnalyze(original_path, hashed_name)
        
    def fileAnalyze(self, filePath: Path, ghidraFileName: str):
        print(f"\n--- Processing {filePath.name} ---")
        
        try:
            from ghidra.util.task import ConsoleTaskMonitor
            monitor = ConsoleTaskMonitor()

            # 0. EXPLICIT PROJECT CREATION: 
            gprPath = self.projectFolder / f"{self.projectName}.gpr"
            if not gprPath.exists():
                print(f"[*] Creating new Ghidra project: {self.projectName}...")
                from ghidra.base.project import GhidraProject
                new_proj = GhidraProject.createProject(str(self.projectFolder.resolve()), self.projectName, False)
                if new_proj:
                    new_proj.close()

            # 1. Boot the modern PyGhidra Project context
            print(f"[*] Opening project via modern PyGhidra context...")
            with pyghidra.open_project(self.projectFolder, self.projectName) as project:
                
                rootFolder = project.getProjectData().getRootFolder()
                
                # 2. Check if the file is already imported
                if not rootFolder.getFile(ghidraFileName):
                    print(f"[*] Importing new file via pyghidra.program_loader...")
                    loader = pyghidra.program_loader().project(project).source(str(filePath.resolve())).name(ghidraFileName)
                    with loader.load() as load_results:
                        load_results.save(monitor)
                
                # 3. Open the cleanly imported file, analyze it, and save it
                print(f"[*] Opening program via pyghidra.program_context...")
                with pyghidra.program_context(project, f"/{ghidraFileName}") as program:
                    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
                    from ghidra.program.model.listing import Program
                    
                    # --- FIX: Use the literal string "Analyzed" ---
                    info_options = program.getOptions(Program.PROGRAM_INFO)
                    if info_options.getBoolean("Analyzed", False):
                        print(f"[*] Program is already marked as analyzed! Skipping redundant analysis.")
                    
                    else:
                        mgr = AutoAnalysisManager.getAnalysisManager(program)
                        mgr.initializeOptions()
                        
                        print(f"[*] Starting auto-analysis (Java errors suppressed)...")
                        
                        # --- JAVA STDERR REDIRECTION ---
                        from java.lang import System
                        from java.io import PrintStream, ByteArrayOutputStream
                        
                        original_err = System.err
                        dummy_stream = ByteArrayOutputStream()
                        System.setErr(PrintStream(dummy_stream))
                        
                        txId = program.startTransaction("Headless Auto-Analysis")
                        try:
                            options = program.getOptions("Analyzers")
                            options.setBoolean("Windows Resource Reference", False)
                            options.setBoolean("PDB Universal", True)

                            mgr.reAnalyzeAll(None)
                            mgr.startAnalysis(monitor)

                            while mgr.isAnalyzing():
                                time.sleep(0.5)

                            program.flushEvents()
                            
                            # Tell the GUI that the script officially completed the auto-analysis
                            info_options.setBoolean("Analyzed", True)
                            
                        finally:
                            program.endTransaction(txId, True)
                            System.setErr(original_err)

                        program.save("Automated analysis via PyGhidra", monitor)
                        print(f"[*] Success! Analyzed and saved into database: {program.getName()}")

        except Exception:
            import traceback
            print(f"[!] Failed to process {ghidraFileName}: \n{traceback.format_exc()}")

if __name__ == "__main__":
    analyzerObj = Analyzer(
        projectFolder=Path("./ghidraProject"),
        projectName="ghidraProject",
        inputPath=Path("/mnt/b/Coding_and_Hacking/OpenCode/TempProject/binaries/DSDriver.sys"),
        localSymbolPath=Path("./symbols"),
        symbolServer="https://msdl.microsoft.com/download/symbols"
    )
    
    analyzerObj.get_symbols()
    
    analyzerObj.ghidraAnalyzeObj.analyze()