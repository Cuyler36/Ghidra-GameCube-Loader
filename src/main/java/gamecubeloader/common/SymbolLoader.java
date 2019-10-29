package gamecubeloader.common;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledFunctionPointer;
import ghidra.app.util.demangler.DemangledMethod;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemangledTemplate;
import ghidra.app.util.demangler.DemangledType;
import ghidra.app.util.demangler.DemangledVariable;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class SymbolLoader {
	private static final long UINT_MASK = 0xFFFFFFFF;
	
	public final static class LoadMapResult {
		public boolean loaded;
		public Map<Long, SymbolInfo> symbolMap;
		
		public LoadMapResult(boolean loaded, Map<Long, SymbolInfo> symbolMap) {
			this.loaded = loaded;
			this.symbolMap = symbolMap;
		}
	}
	
	private Program program;
	private TaskMonitor monitor;
	private AddressSpace addressSpace;
	private String[] lines;
	private List<SymbolInfo> symbols;
	private long objectAddress = 0;
	private int alignment;
	private long bssAddress;
	private String binaryName;
	
	public SymbolLoader(Program program, TaskMonitor monitor, FileReader reader, long objectAddress, int alignment, long bssAddress,
			String binaryName) {
		this.program = program;
		this.monitor = monitor;
		this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		this.lines = new BufferedReader(reader).lines().toArray(String[]::new);
		this.objectAddress = objectAddress;
		this.alignment = alignment;
		this.bssAddress = bssAddress;
		
		this.binaryName = binaryName;
	}
	
	private List<MemoryMapSectionInfo> GetMemoryMapInfo() {
		List<MemoryMapSectionInfo> memMapInfo = new ArrayList<MemoryMapSectionInfo>();
		int memMapLineStartIdx = -1;
		
		// Start by grabbing the memory map index.
		// TODO: Some early symbol files do not contain a memory map section. Handle these.
		for (int i = lines.length - 1; i > -1; i--) {
			if (lines[i].contains("Memory map:")) {
				memMapLineStartIdx = i + 2; // Add three to skip the header lines.
				break;
			}
		}
		
		if (memMapLineStartIdx > -1) {
			// Parse the memory map info.
			for (int i = memMapLineStartIdx; i < lines.length; i++) {
				String line = lines[i];
				if (line.equals("") || line.trim().length() == 0) {
					break;
				}
				
				// Split the string by whitespace entries.
				String[] splitInformation = line.trim().split("\\s+");
				
				// Try to parse the information.
				
				// Valid lines have four entries. Name -> Starting Address -> Size -> File Offset
				if (splitInformation.length == 0) break;
				else if (splitInformation.length < 4) continue;
				
				try {
					String name = splitInformation[0];
					long startingAddress = Long.parseUnsignedLong(splitInformation[1], 16) & UINT_MASK;
					long size = Long.parseUnsignedLong(splitInformation[2], 16) & UINT_MASK;
					long fileOffset = Long.parseUnsignedLong(splitInformation[3], 16) & UINT_MASK;
					
					if (size > 0) {
						memMapInfo.add(new MemoryMapSectionInfo(name, startingAddress, size, fileOffset));
					}
				}
				catch (NumberFormatException e) {
					Msg.error(this, "Symbol Loader: Failed to parse memory map entry: " + splitInformation[0]);
				}
			}
			
			// The first section should start at the base address.
			if (memMapInfo.size() > 0 && memMapInfo.get(0).fileOffset != 0) {
				long adjustOffset = memMapInfo.get(0).fileOffset;
				for (MemoryMapSectionInfo info : memMapInfo) {
					if (info.fileOffset != 0)
					{
						info.fileOffset -= adjustOffset;
					}
				}
			}
			
			
			return memMapInfo;
		}
		
		// TODO: This shouldn't be thrown for symbol maps that are previous formats.
		Msg.warn(this, "Symbol Loader: The memory map information couldn't be located. This symbol map may not be loaded correctly.");
		return memMapInfo;
	}
	
	private void ParseSymbols() {
		symbols = new ArrayList<SymbolInfo>();
		List<MemoryMapSectionInfo> memMapInfo = GetMemoryMapInfo();
		
		if (memMapInfo != null) {
			long currentSectionSize = 0;
			long effectiveAddress = this.objectAddress;
			long preBssAddress = -1;
			
			for (int i = 0; i < lines.length; i++) {
				String line = lines[i];
				if (line.equals("") || line.trim().length() == 0) continue;
				
				if (line.contains(" section layout")) {
					String sectionName = line.substring(0, line.indexOf(" section layout")).trim();
					Msg.info(this, "Symbol Loader: Switched to symbols for section: " + sectionName);
					
					// Search the info list for the section.
					MemoryMapSectionInfo currentSectionInfo = null;
					for (MemoryMapSectionInfo sectionInfo : memMapInfo) {
						if (sectionInfo.name.equals(sectionName)) {
							currentSectionInfo = sectionInfo;
							break;
						}
					}
					
					if (currentSectionInfo != null) {
						effectiveAddress += currentSectionSize;
						currentSectionSize = currentSectionInfo.size;
						
						// Align the effective address to the section alignment.
						if (alignment > 0) {
							effectiveAddress += (alignment - (effectiveAddress % alignment));
						}
						
						// Check if we should switch to using the bss section address.
						if (currentSectionInfo.name.equals(".bss") && bssAddress != -1) {
							preBssAddress = effectiveAddress;
							effectiveAddress = bssAddress;
						}
						else if (preBssAddress > -1) {
							effectiveAddress = preBssAddress;
							preBssAddress = 0;
						}
						
						// Try to rename the memory block.
						this.TryRenameMemoryBlocks(currentSectionInfo, effectiveAddress);
					}
					else {
						Msg.warn(this, "Symbol Loader: No memory layout information was found for section: " + sectionName);
					}
					
					if (i + 1 < lines.length && lines[i + 1].trim().startsWith("Starting")) {
						i += 3; // Skip past the section column data.
					}
				}
				else {
					var entryInfoStart = line.indexOf("(entry of ");
					if (entryInfoStart > -1) {
						var entryInfoEnd = line.indexOf(')');
						if (entryInfoEnd > -1) {
							line = line.substring(0, entryInfoStart) + line.substring(entryInfoEnd + 1);
						}
					}
					
					String[] splitInformation = line.trim().split("\\s+");
					if (splitInformation.length < 5) continue;
					
					long startingAddress = 0;
					long size = 0;
					long virtualAddress = 0;
					int objectAlignment = 0;
					
					try {
						startingAddress = Long.parseUnsignedLong(splitInformation[0], 16) & UINT_MASK;
						size = Long.parseUnsignedLong(splitInformation[1], 16) & UINT_MASK;
						virtualAddress = Long.parseUnsignedLong(splitInformation[2], 16) & UINT_MASK;
					}
					catch (Exception e) {
						//Msg.error(this, "Symbol Loader: Unable to parse symbol information for symbol: " + line);
						continue;
					}
					
					try {
						objectAlignment = Integer.parseInt(splitInformation[3]);
						if (objectAlignment == 1) continue;
					}
					catch (NumberFormatException e) {
						// Do nothing for the object alignment.
					}
						
					SymbolInfo symbolInfo = null;
					
					if (virtualAddress < 0x80000000L && virtualAddress < this.addressSpace.getMaxAddress().getUnsignedOffset()) {
						// Dolphin Emulator & DOL map files have their virtual address pre-calculated.
						virtualAddress += effectiveAddress;
					}

					if (entryInfoStart > -1)
					{
						symbolInfo = new SymbolInfo(splitInformation[3], splitInformation.length < 5 ? "" : splitInformation[4], startingAddress,
							size, virtualAddress, 0);
					}
					else {
						symbolInfo = new SymbolInfo(splitInformation[4], splitInformation.length < 6 ? "" : splitInformation[5], startingAddress,
							size, virtualAddress, objectAlignment);
					}
					
					symbols.add(symbolInfo);
				}
			}
		}
	}
	
	private String TryRenameMemoryBlocks(MemoryMapSectionInfo sectionInfo, long sectionAddress) {
		if (sectionInfo.startingAddress >= this.objectAddress &&
			sectionInfo.startingAddress < this.addressSpace.getMaxAddress().getOffset()) {
				sectionAddress = sectionInfo.startingAddress;
		}
	
		var name = sectionInfo.name;
		var address = this.addressSpace.getAddress(sectionAddress);
		var memoryBlock = this.program.getMemory().getBlock(address);
		if (memoryBlock != null) {
			try {
				var blockName = memoryBlock.getName();
				var originalName = memoryBlock.getName();
				if (blockName.contains("_")) {
					blockName = blockName.substring(0, blockName.lastIndexOf("_"));
				}
				blockName += "_" + name;
				memoryBlock.setName(blockName);
				this.renameFragment(address, blockName);
				
				Msg.info(this, String.format("Symbol Loader: set memory block name of %s to %s!", originalName, memoryBlock.getName()));
				if (name.toLowerCase().contains("rodata")) {
					memoryBlock.setWrite(false);
					memoryBlock.setRead(true);
				}
				
				return memoryBlock.getName();
			} catch (DuplicateNameException | LockException e) {
				e.printStackTrace();
				return memoryBlock.getName();
			}
		}
		
		return name;
	}
	
	private void renameFragment(Address blockStart, String blockName) {
		String[] treeNames = this.program.getListing().getTreeNames();
		for (int i = 0; i < treeNames.length; ++i) {
			ProgramFragment frag = this.program.getListing().getFragment(treeNames[i], blockStart);
			
			try {
				frag.setName(blockName);
			}
			catch (DuplicateNameException e) {
				e.printStackTrace();
			}
		}
	}
	
	public Map<Long, SymbolInfo> ApplySymbols() {
		this.ParseSymbols();
		
		// Create a Map<long, SymbolInfo> for use with relocation table creation.
		Map<Long, SymbolInfo> symbolMap = new HashMap<Long, SymbolInfo>();
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace globalNamespace = program.getGlobalNamespace();
		Listing listing = program.getListing();
		
		var demanglerOptions = new DemanglerOptions();
		demanglerOptions.setApplySignature(true);

		for (SymbolInfo symbolInfo : symbols)
		{
			if (symbolInfo.alignment == 1) continue; // Don't bother loading these for now.
			
			// If a symbol with the current address isn't already present at the address, add it.
			if (!symbolMap.containsKey(symbolInfo.virtualAddress)) {
				symbolMap.put(symbolInfo.virtualAddress, symbolInfo);
			}
			
			var symbolAddress = this.addressSpace.getAddress(symbolInfo.virtualAddress);
			
			// Demangle the name using CodeWarriors scheme.
			DemangledObject demangledNameObject = null;
			try {
				demangledNameObject = CodeWarriorDemangler.demangleSymbol(symbolInfo.name);
			} catch(Exception e) {
				// TODO(jstpierre): Investigate the failed demanglings. Sometimes these are literal symbols.
				demangledNameObject = null;
			}

			var demangledName = demangledNameObject == null ? symbolInfo.name : demangledNameObject.getName();
			
			// Determine namespace
			Namespace objectNamespace = null;
			
			try {
				String namespaceName = symbolInfo.container;
				
				if (namespaceName.equals("")) {
					objectNamespace = globalNamespace;
				}
				else {
					int fileTypeIdx = namespaceName.lastIndexOf('.');
					if (fileTypeIdx > -1)
					{
						namespaceName = namespaceName.substring(0, fileTypeIdx);
					}
					
					objectNamespace = symbolTable.getNamespace(namespaceName, globalNamespace);
					
					if (objectNamespace == null) {
						objectNamespace = symbolTable.createNameSpace(globalNamespace, namespaceName, SourceType.IMPORTED);
					}
				}
				
				// Now apply the demangled namespace if one exists.
				if (demangledNameObject != null) {
					var demangledNamespace = demangledNameObject.getNamespace();
					
					if (demangledNamespace != null && demangledNamespace != globalNamespace) {
						var realNamespace = symbolTable.getNamespace(demangledNamespace.getName(), objectNamespace);
						if (realNamespace == null) {
							realNamespace = symbolTable.createNameSpace(objectNamespace, demangledNamespace.getName(), SourceType.IMPORTED);
						}
						
						objectNamespace = realNamespace;
					}
				}
			}
			catch (DuplicateNameException | InvalidInputException e) {
				// Do nothing. This should never throw for DuplicateNameException.
				Msg.error(this, "Symbol Loader: An error occurred while creating a namespace for: " + symbolInfo.container);
				e.printStackTrace();
			}
			
			try {
				symbolTable.createLabel(symbolAddress, demangledName, objectNamespace == null ? globalNamespace : objectNamespace, SourceType.ANALYSIS);
				
				// If it's a function, create it.
				var block = this.program.getMemory().getBlock(symbolAddress);
				if (symbolInfo.size > 3 && block != null && block.isExecute()) {
					var addressSet = new AddressSet(symbolAddress, this.addressSpace.getAddress(symbolInfo.virtualAddress + symbolInfo.size - 1));
					try {
						this.program.getFunctionManager().createFunction(demangledName, objectNamespace == null ? globalNamespace : objectNamespace,
								symbolAddress, addressSet, SourceType.ANALYSIS);
					}
					catch (OverlappingFunctionException | IllegalArgumentException e) {
						e.printStackTrace();
					}
				}
				
				// Try applying the function arguments & return type using the demangled info.
				if (demangledNameObject != null) {
					try {
						boolean res = demangledNameObject.applyTo(program, this.addressSpace.getAddress(symbolInfo.virtualAddress), demanglerOptions, monitor);
					}
					catch (Exception e) {						
						e.printStackTrace();
					}
					
				}
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Symbol Loader: An error occurred when attempting to load symbol: " + symbolInfo.name);
			}
		}
		
		return symbolMap;
	}
	
	public static LoadMapResult TryLoadAssociatedMapFile(String binaryName, File directory, Program program, TaskMonitor monitor,
			long objectAddress, int alignment, long bssAddress) {
		if (directory == null) return new LoadMapResult(false, null);
		
		var files = directory.listFiles();
		
		for (var i = 0; i < files.length; i++) {
			var fileName = files[i].getName();
			
			if (fileName.endsWith(binaryName + ".map")) {
				FileReader fileReader;
				
				try {
					fileReader = new FileReader(files[i]);
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					return new LoadMapResult(false, null);
				}
			
				var loader = new SymbolLoader(program, monitor, fileReader, objectAddress, alignment, bssAddress, binaryName);
				return new LoadMapResult(true, loader.ApplySymbols());
			}
		}
		
		return new LoadMapResult(false, null);
	}

	public static class CodeWarriorDemangler {
		public String str;
		public boolean containsInvalidSpecifier;

		public CodeWarriorDemangler(String g) {
			this.str = g;
		}

		public boolean isEmpty() { return this.str == null || this.str.length() < 1; }
		public String cw(int n) { String g = this.str.substring(0, n); this.str = this.str.substring(n); return g; }
		public char hd() { return isEmpty() ? 0 : this.str.charAt(0); }
		public char tk() { char hd = this.hd(); cw(1); return hd; }

		public int nextInteger(char initial) {
			int value = initial - '0';

			while (Character.isDigit(hd()))
				value = value * 10 + (tk() - '0');

			return value;
		}

		public int nextInteger() {
			assert Character.isDigit(hd());
			return nextInteger(tk());
		}

		public boolean hasFunction() {
			return hd() == 'F';
		}

		public DemangledTemplate nextTemplate() {
			assert hd() == '<';

			// Parse a type, then look for the comma.
			var template = new DemangledTemplate();
			while (true) {
				var tok = tk();
				if (tok == '>')
					break;
				assert tok == '<' || tok == ',';

				var type = this.nextType();
				template.addParameter(type);
			}
			return template;
		}

		private static void demangleTemplates(DemangledDataType o) {
			var name = o.getName();
			var lb = name.indexOf('<');
			if (lb < 0)
				return;
			var rb = name.lastIndexOf('>');
			var parser = new CodeWarriorDemangler(name.substring(lb, rb + 1));
			o.setName(name.substring(0, lb));
			o.setTemplate(parser.nextTemplate());
		}

		private static void demangleTemplates(DemangledFunction o) {
			var name = o.getName();
			var lb = name.indexOf('<');
			if (lb < 0)
				return;
			var rb = name.lastIndexOf('>');
			var parser = new CodeWarriorDemangler(name.substring(lb, rb + 1));
			o.setName(name.substring(0, lb));
			o.setTemplate(parser.nextTemplate());
		}

		public static DemangledObject demangleSymbol(String symbolName) {
			// If it doesn't have a __, then it's not mangled.
			if (!symbolName.contains("__"))
				return null;
	
			// If we start with "@x@", then we're a virtual thunk, with "x" being the offset to the this pointer.
			boolean isThunk = false;
			if (symbolName.startsWith("@")) {
				int thunkAddrIdx = symbolName.lastIndexOf('@');
				symbolName = symbolName.substring(thunkAddrIdx + 1);
				isThunk = true;
			}

			int firstDunder = symbolName.indexOf("__", 1);
			// If the symbol starts with __, exit.
			if (firstDunder < 0)
				return null;
			
			String parameters = symbolName.substring(firstDunder + 2);
			// After the dunder comes the class, if it exists, followed by 'F', followed by parameters.
			var demangler = new CodeWarriorDemangler(parameters);

			DemangledDataType parentClass = null;
			if (!demangler.hasFunction())
				parentClass = demangler.nextType();
	
			if (demangler.hasFunction()) {
    			var d = demangler.nextFunction(parentClass);
    
    			if (isThunk)
    				d.setThunk(true);
    
    			String functionName = symbolName.substring(0, firstDunder);
    			String operatorName = demangleSpecialOperator(functionName);
    	
    			if (operatorName != null) {
    				d.setOverloadedOperator(true);
    				d.setName(operatorName);
    			} else {
    				if (functionName.equals("__ct"))
    					functionName = parentClass.getName();
    				else if (functionName.equals("__dt"))
    					functionName = "~" + parentClass.getName();
    	
    				d.setName(functionName);
    	
    				CodeWarriorDemangler.demangleTemplates(d);
    			}
    
    			d.setOriginalMangled(symbolName);
    			
    			if (demangler.containsInvalidSpecifier)
    				return null;
    			
    			return d;
			}
			
            // It could be a member or vtable
            if (demangler.isEmpty()) {
                var member = new DemangledVariable(symbolName.substring(0, firstDunder));
                
                if (parentClass != null) {
                    var namespace = parentClass.getNamespace();
                    var className = parentClass.getDemangledName();
                    // If the class has a namespace, include that as well.
                    if (parentClass.getTemplate() != null)
                        className += parentClass.getTemplate().toTemplate();
                    var classNamespace = new DemangledType(className);
                    classNamespace.setNamespace(namespace);
                    member.setNamespace(classNamespace);
                }
                
                return member;
            }
			
			return null;
		}

		public DemangledFunction nextFunction(DemangledDataType parentClass) {
			char tok = tk();

			DemangledFunction func;
			if (parentClass != null) {
				func = new DemangledMethod(null);
			} else {
				func = new DemangledFunction(null);
			}

			if (tok == 'C') {
				func.setTrailingConst();
				tok = tk();
			}
			assert tok == 'F';

			// Parse parameters.
			while (true) {
				if (this.str.length() == 0)
					break;

				tok = hd();
				if (tok == '_') {
					tk();
					func.setReturnType(this.nextType());
				} else {
					func.addParameter(this.nextType());
				}
			}

			if (parentClass != null) {
				var namespace = parentClass.getNamespace();
				var className = parentClass.getDemangledName();
				// If the class has a namespace, include that as well.
				if (parentClass.getTemplate() != null)
					className += parentClass.getTemplate().toTemplate();
				var classNamespace = new DemangledType(className);
				classNamespace.setNamespace(namespace);
				func.setNamespace(classNamespace);
			}

			return func;
		}

		public DemangledDataType nextType() {
			char tok = tk();

			if (Character.isDigit(tok)) {
				// Name or literal integer. Literal integers can show up in template parameters.
				int value = nextInteger(tok);
				if (hd() == '>' || hd() == ',') {
					// Literal integer (template)
					return new DemangledDataType("" + value);
				} else {
					// Name.
					var d = new DemangledDataType(cw(value));
					demangleTemplates(d);
					return d;
				}
			} else if (tok == 'Q') {
				// Qualified name.
				int compCount = tk() - '0';

				var names = new ArrayList<String>();
				for (var i = 0; i < compCount; i++) {
					int length = nextInteger();
					names.add(cw(length));
				}

				var d = new DemangledDataType(names.get(compCount - 1));
				demangleTemplates(d);
				d.setNamespace(DemanglerUtil.convertToNamespaces(names.subList(0, names.size() - 1)));
				return d;
			} else if (tok == 'F') {
				var func = new DemangledFunctionPointer();

				// Parse parameters.
				while (true) {
					if (this.str.length() == 0)
						break;

					tok = hd();
					
					if (tok == '_') {
						tk();
						func.setReturnType(this.nextType());
						break;
					} else {
						func.addParameter(this.nextType());
					}
				}

				demangleTemplates(func);

				return func;
			} else if (tok == 'P') {
				var d = this.nextType();
				d.incrementPointerLevels();
				return d;
			} else if (tok == 'A') {
				var arraySize = this.nextInteger();
				var typeSeparator = tk();
				assert typeSeparator  == '_';
				var d = this.nextType();
				d.setArray(arraySize);
				return d;
			} else if (tok == 'R') {
				var d = this.nextType();
				d.setReference();
				return d;
			} else if (tok == 'C') {
				var d = this.nextType();
				d.setConst();
				return d;
			} else if (tok == 'U') {
				var d = this.nextType();
				d.setUnsigned();
				return d;
			} else if (tok == 'S') {
				var d = this.nextType();
				d.setSigned();
				return d;
			} else if (tok == 'M') {
				int length = nextInteger();
				var scope = cw(length);
				var d = this.nextType();
				d.setMemberScope(scope);
				return d;
			} else if (tok == 'i') {
				return new DemangledDataType(DemangledDataType.INT);
			} else if (tok == 'l') {
				return new DemangledDataType(DemangledDataType.LONG);
			} else if (tok == 'x') {
				return new DemangledDataType(DemangledDataType.LONG_LONG);
			} else if (tok == 'b') {
				return new DemangledDataType(DemangledDataType.BOOL);
			} else if (tok == 'c') {
				return new DemangledDataType(DemangledDataType.CHAR);
			} else if (tok == 's') {
				return new DemangledDataType(DemangledDataType.SHORT);
			} else if (tok == 'f') {
				return new DemangledDataType(DemangledDataType.FLOAT);
			} else if (tok == 'd') {
				return new DemangledDataType(DemangledDataType.DOUBLE);
			} else if (tok == 'w') {
				return new DemangledDataType(DemangledDataType.WCHAR_T);
			} else if (tok == 'v') {
				return new DemangledDataType(DemangledDataType.VOID);
			} else if (tok == 'e') {
				return new DemangledDataType(DemangledDataType.VARARGS);
			} else {
				// Unknown.
				this.containsInvalidSpecifier = this.containsInvalidSpecifier || tok != '_'; // This is here in case the __ is preceded by more underscores.
				return new DemangledDataType(DemangledDataType.UNDEFINED);
			}
		}

		private static String demangleSpecialOperator(String symbolName) {
			if (symbolName.startsWith("__")) {
				String opName = symbolName.substring(2);
	
				if (opName.equals("nw"))
					return "operator new";
				else if (opName.equals("nwa"))
					return "operator new[]";
				else if (opName.equals("dl"))
					return "operator delete";
				else if (opName.equals("dla"))
					return "operator delete[]";
				else if (opName.equals("pl"))
					return "operator +";
				else if (opName.equals("mi"))
					return "operator -";
				else if (opName.equals("ml"))
					return "operator *";
				else if (opName.equals("dv"))
					return "operator /";
				else if (opName.equals("md"))
					return "operator %";
				else if (opName.equals("er"))
					return "operator ^";
				else if (opName.equals("adv"))
					return "operator /=";
				else if (opName.equals("or"))
					return "operator |";
				else if (opName.equals("co"))
					return "operator ~";
				else if (opName.equals("nt"))
					return "operator !";
				else if (opName.equals("as"))
					return "operator =";
				else if (opName.equals("lt"))
					return "operator <";
				else if (opName.equals("gt"))
					return "operator >";
				else if (opName.equals("apl"))
					return "operator +=";
				else if (opName.equals("ami"))
					return "operator -=";
				else if (opName.equals("amu"))
					return "operator *=";
				else if (opName.equals("amd"))
					return "operator %=";
				else if (opName.equals("aer"))
					return "operator ^=";
				else if (opName.equals("aad"))
					return "operator &=";
				else if (opName.equals("aor"))
					return "operator |=";
				else if (opName.equals("ls"))
					return "operator <<";
				else if (opName.equals("rs"))
					return "operator >>";
				else if (opName.equals("ars"))
					return "operator >>=";
				else if (opName.equals("als"))
					return "operator <<=";
				else if (opName.equals("eq"))
					return "operator ==";
				else if (opName.equals("ne"))
					return "operator !=";
				else if (opName.equals("le"))
					return "operator <=";
				else if (opName.equals("aa"))
					return "operator &&";
				else if (opName.equals("oo"))
					return "operator ||";
				else if (opName.equals("pp"))
					return "operator ++";
				else if (opName.equals("mm"))
					return "operator --";
				else if (opName.equals("cl"))
					return "operator ()";
				else if (opName.equals("vc"))
					return "operator []";
				else if (opName.equals("rf"))
					return "operator ->";
				else if (opName.equals("cm"))
					return "operator ,";
				else if (opName.equals("rm"))
					return "operator ->*";
			}
	
			return null;
		}	
	}

	public static void main(String[] args) {
		var demangledType = CodeWarriorDemangler.demangleSymbol("ConvertOffsToPtr<Q44nw4r3lyt3res6TexMap>__Q34nw4r3lyt6detailFPCvUi_PCQ44nw4r3lyt3res6TexMap");
		System.out.println(demangledType.getSignature(true));
	}
}
