package gamecubeloader.common;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
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
						Msg.error(this, "Symbol Loader: Unable to parse symbol information for symbol: " + line);
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
					
					if (virtualAddress < objectAddress && virtualAddress < this.addressSpace.getMaxAddress().getUnsignedOffset()) {
						// Dolphin Emulator & DOL map files have their virtual address pre-calculated.
						virtualAddress += effectiveAddress;
					}

					if (entryInfoStart > -1)
					{
						symbolInfo = new SymbolInfo(splitInformation[3], splitInformation.length >= 4 ? "" : splitInformation[4], startingAddress,
							size, virtualAddress, 0);
					}
					else {
						symbolInfo = new SymbolInfo(splitInformation[4], splitInformation.length >= 5 ? "" : splitInformation[5], startingAddress,
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
					blockName = blockName.substring(0, blockName.indexOf("_"));
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
	
	public void ApplySymbols() {
		this.ParseSymbols();
		
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace globalNamespace = program.getGlobalNamespace();
		
		var demanglerOptions = new DemanglerOptions();
		demanglerOptions.setApplySignature(true);
		
		for (SymbolInfo symbolInfo : symbols)
		{
			if (symbolInfo.alignment == 1) continue; // Don't bother loading these for now.
			
			// Demangle name first.
			var demangledNameObject = DemanglerUtil.demangle(symbolInfo.name);
			var demangledName = demangledNameObject == null ? symbolInfo.name : demangledNameObject.getName();
			
			// Ghidra's built-in demangler doesn't handle properly demangling constructors and destructors.
			if (demangledNameObject != null) {
				if (demangledName.contains("__ct")) {
					if (demangledNameObject.getNamespace() != null ) {
						demangledName = demangledNameObject.getNamespace().getDemangledName();
						demangledNameObject.setName(demangledName);
					}
				}
				else if (demangledName.contains("__dt")) {
					if (demangledNameObject.getNamespace() != null) {
						demangledName = "~" + demangledNameObject.getNamespace().getDemangledName();
						demangledNameObject.setName(demangledName);
					}
				}
			}

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
				var symbolAddress = this.addressSpace.getAddress(symbolInfo.virtualAddress);
				symbolTable.createLabel(symbolAddress, demangledName, objectNamespace == null ? globalNamespace : objectNamespace, SourceType.ANALYSIS);
				
				// If it's a function, create it.
				if (symbolInfo.size > 3 && this.program.getMemory().getBlock(symbolAddress).isExecute()) {
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
						demangledNameObject.applyTo(program, this.addressSpace.getAddress(symbolInfo.virtualAddress), demanglerOptions, monitor);
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
	}
	
	public static boolean TryLoadAssociatedMapFile(String binaryName, File directory, Program program, TaskMonitor monitor, long objectAddress, int alignment,
			long bssAddress) {
		if (directory == null) return false;
		
		var files = directory.listFiles();
		
		for (var i = 0; i < files.length; i++) {
			var fileName = files[i].getName();
			
			if (fileName.endsWith(binaryName + ".map")) {
				FileReader fileReader;
				
				try {
					fileReader = new FileReader(files[i]);
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					return false;
				}
			
				var loader = new SymbolLoader(program, monitor, fileReader, objectAddress, alignment, bssAddress, binaryName);
				loader.ApplySymbols();
				return true;
			}
		}
		
		return false;
	}
}
