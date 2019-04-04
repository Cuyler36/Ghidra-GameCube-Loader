package gamecubeloader.rel;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import gamecubeloader.common.SymbolLoader;
import gamecubeloader.common.Yaz0;
import gamecubeloader.dol.DOLHeader;
import gamecubeloader.dol.DOLProgramBuilder;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskMonitor;

public class RELProgramBuilder  {
	private RELHeader rel;
	
	private DOLHeader dol;
	private BinaryReader dolReader;
	
	private long baseAddress;
	private AddressSpace addressSpace;
	private Program program;
	private MemoryConflictHandler memConflictHandler;
	private MemoryBlockUtil memoryBlockUtil;
	private TaskMonitor monitor;
	
	private static final int IMPORT_ENTRY_SIZE = 8;
	private static final int RELOCATION_SIZE = 8;
	
	// Relocation types supported by OSLink.
	private static final short R_PPC_NONE = 0;
	private static final short R_PPC_ADDR32 = 1;
	private static final short R_PPC_ADDR24 = 2;
	private static final short R_PPC_ADDR16 = 3;
	private static final short R_PPC_ADDR16_LO = 4;
	private static final short R_PPC_ADDR16_HI = 5;
	private static final short R_PPC_ADDR16_HA = 6;
	private static final short R_PPC_ADDR14 = 7;
	private static final short R_PPC_ADDR14_BRTAKEN = 8;
	private static final short R_PPC_ADDR14_BRNTAKEN = 9;
	private static final short R_PPC_REL24 = 10;
	private static final short R_PPC_REL14 = 11;
	private static final short R_PPC_REL14_BRTAKEN = 12;
	private static final short R_PPC_REL14_BRNTAKEN = 13;
	
	private static final short R_DOLPHIN_NOP = 201;
	private static final short R_DOLPHIN_SECTION = 202;
	private static final short R_DOLPHIN_END = 203;
	private static final short R_DOLPHIN_MAKEREF = 204;
	
	private final class ImportEntry {
		public long moduleId;
		public long offset;
		
		public ImportEntry(long moduleId, long offset) {
			this.moduleId = moduleId;
			this.offset = offset;
		}
	}
	
	private final class Relocation {
		public int offset;
		public int type;
		public int section;
		public long addend;
		
		public Relocation(int offset, int type, int section, long addend) {
			this.offset = offset;
			this.type = type;
			this.section = section;
			this.addend = addend;
		}
	}
	
	private final class RelocatableModuleInfo {
		public RELHeader header;
		public BinaryReader reader;
		public String name;
		
		public RelocatableModuleInfo (RELHeader header, BinaryReader reader, String name) {
			this.header = header;
			this.reader = reader;
			this.name = name;
		}
	}
	
	public RELProgramBuilder(RELHeader rel, ByteProvider provider, Program program,
			MemoryConflictHandler memConflictHandler, TaskMonitor monitor)
					throws IOException, AddressOverflowException, AddressOutOfBoundsException, MemoryAccessException {
		this.rel = rel;
		this.program = program;
		this.memConflictHandler = memConflictHandler;
		this.memoryBlockUtil = new MemoryBlockUtil(program, memConflictHandler);
		this.monitor = monitor;
		
		this.load(provider);
	}
	
	protected void load(ByteProvider provider)
			throws IOException, AddressOverflowException, AddressOutOfBoundsException, MemoryAccessException {
		this.baseAddress = 0x80000000;
		this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		var relArray = new ArrayList<RelocatableModuleInfo>();
		relArray.add(new RelocatableModuleInfo(rel, new BinaryReader(provider, false), FilenameUtils.getBaseName(provider.getName())));
		
		var directory = provider.getFile().getParentFile();
		var files = directory.listFiles();
		for (var i = 0; i < files.length; i++) {
			var fileName = files[i].getName();
			
			if (fileName == provider.getFile().getName()) continue;
			
			if (this.dol == null && fileName.endsWith(".dol")) {
				var dolProvider = new RandomAccessByteProvider(files[i]);
				var dolReader = new BinaryReader(dolProvider, false);
				var dolHeader = new DOLHeader(dolReader);
				
				if (dolHeader.CheckHeaderIsValid()) {
					this.dol = dolHeader;
					this.dolReader = dolReader;
				}
			}
			else if (fileName.endsWith(".rel") || fileName.endsWith(".szs") || fileName.endsWith(".yaz0")) {
				ByteProvider relProvider = new RandomAccessByteProvider(files[i]);
				var relReader = new BinaryReader(relProvider, false);
				
				var yaz0 = new Yaz0();
				if (yaz0.IsValid(relProvider)) {
					relProvider = yaz0.Decompress(relProvider);
					relReader = new BinaryReader(relProvider, false);
				}
				
				var relHeader = new RELHeader(relReader);
				if (relHeader.IsValid(relReader)) {
					// Verify no other modules with the same module id exist before loading.
					var invalid = false;
					for (var x = 0; x < relArray.size(); x++) {
						if (relArray.get(x).header.moduleId == relHeader.moduleId) {
							invalid = true;
							break;
						}
					}
					
					if (invalid == false) {
						relArray.add(new RelocatableModuleInfo(relHeader, relReader, FilenameUtils.getBaseName(files[i].getName())));
					}
					else {
						relProvider.close();
					}
				}
				else {
					relProvider.close();
				}
			}
		}
		
		var currentOutputAddress = 0x80000000L;
		
		// If a DOL file exists, load it first.
		if (this.dol != null) {
			new DOLProgramBuilder(this.dol, this.dolReader.getByteProvider(), this.program, this.memConflictHandler, this.monitor);
			currentOutputAddress = align(this.dol.memoryEndAddress, 0x20);
		}
		
		// Load all rel files based on their module id.
		relArray.sort((a, b) -> a.header.moduleId < b.header.moduleId ? -1 : 1); // Sort rel headers based on their module ids.
		var relBaseAddress = 0L;
		
		for (var i = 0; i < relArray.size(); i++) {
			var relInfo = relArray.get(i);
			relInfo.header.bssSectionId = 0;
			relBaseAddress = currentOutputAddress;
			
			var textCount = 0;
			var dataCount = 0;
			for (var s = 0; s < relInfo.header.sectionCount; s++) {
				var section = relInfo.header.sections[s];
				if (section.size != 0) {
					if (section.address != 0) {
						var isText = (section.address & 1) != 0;
						var blockName = String.format("%s_%s%d", relInfo.name, isText ? ".text" : ".data", isText ? textCount : dataCount);
						
						this.memoryBlockUtil.createInitializedBlock(blockName, this.addressSpace.getAddress(currentOutputAddress),
								relInfo.reader.getByteProvider().getInputStream(section.address & ~1), section.size, "", null, true, true, isText, this.monitor);
						
						if (isText) textCount++;
						else dataCount++;
						
						// Update the address of the section with it's virtual memory address.
						section.address = currentOutputAddress;
						
						currentOutputAddress += section.size;
					}
					else if (relInfo.header.bssSectionId == 0) {
						relInfo.header.bssSectionId = s;
					}
				}
			}
			
			// Add bss section.
			if (relInfo.header.bssSize != 0 && relInfo.header.bssSectionId != 0) {
				if (relInfo.header.moduleVersion < 2 || relInfo.header.bssSectionAlignment == 0) {
					currentOutputAddress = align(currentOutputAddress, 0x20);
				}
				else {
					currentOutputAddress = align(currentOutputAddress, (int) relInfo.header.bssSectionAlignment);
				}
				
				this.memoryBlockUtil.createUninitializedBlock(false, relInfo.name + "_.bss", this.addressSpace.getAddress(currentOutputAddress), relInfo.header.bssSize,
						"", null, true, true, false);
				
				// Set the bss virtual memory address.
				relInfo.header.sections[relInfo.header.bssSectionId].address = currentOutputAddress;
				
				currentOutputAddress += relInfo.header.bssSize;
			}
			
			// Align the output address for the next module.
			currentOutputAddress = align(currentOutputAddress, 0x20);
			
			// Ask if the user wants to load a symbol map file.
			if (OptionDialog.showOptionNoCancelDialog(null, "Load Symbols?", String.format("Would you like to load a symbol map for the relocatable module %s?", relInfo.name),
					"Yes", "No", null) == 1) {
				var fileChooser = new GhidraFileChooser(null);
				fileChooser.setCurrentDirectory(provider.getFile().getParentFile());
				fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
				var selectedFile = fileChooser.getSelectedFile(true);
				
				if (selectedFile != null) {
					var reader = new FileReader(selectedFile);
					var loader = new SymbolLoader(this.program, monitor, reader, relBaseAddress, 0, 0);
					loader.ApplySymbols();
				}
			}
		}
		
		// Apply relocations.
		for (var thisRel = 0; thisRel < relArray.size(); thisRel++) {
			// Do relocations against the DOL file first if it exists.
			if (this.dol != null) {
				this.Relocate(null, relArray.get(thisRel).header, relArray.get(thisRel).reader);
			}
			
			// Now do relocations against modules.
			for (var otherRel = 0; otherRel < relArray.size(); otherRel++) {
				this.Relocate(relArray.get(otherRel).header, relArray.get(thisRel).header, relArray.get(thisRel).reader);
			}
		}
	}
	
	private static long align(long address, int alignment) {
		var inverse = alignment - 1;
		if ((address & inverse) != 0) {
			address = (address + inverse) & ~inverse;
		}
		
		return address;
	}
	
	private boolean Relocate(RELHeader otherModule, RELHeader thisModule, BinaryReader thisReader)
			throws IOException, MemoryAccessException {
		var otherModuleId = otherModule == null ? 0 : otherModule.moduleId;
		var programMemory = this.program.getMemory();
		
		var importTableEntryCount = (int) (thisModule.importTableSize / RELProgramBuilder.IMPORT_ENTRY_SIZE);
		var importEntries = new ImportEntry[importTableEntryCount];
		
		// Seek to the import table.
		thisReader.setPointerIndex(thisModule.importTableOffset);
		
		// Load import entries.
		for (var i = 0; i < importTableEntryCount; i++) {
			importEntries[i] = new ImportEntry(thisReader.readNextUnsignedInt(), thisReader.readNextUnsignedInt());
		}
		
		// Begin relocations.
		for (var i = 0; i < importEntries.length; i++) {
			// Skip any entries that aren't imports from the "otherModule".
			if (importEntries[i].moduleId != otherModuleId) continue; 
			
			Msg.info(this, String.format("Relocations: Starting relocations for module %d from module %d", thisModule.moduleId, otherModuleId));
			
			// Seek to the beginning of this entry's relocation data.
			thisReader.setPointerIndex(importEntries[i].offset);
			
			// Begin applying relocations.
			var importsFinished = false;
			var writeAddress = 0L;
			var writeValue = 0L;
			
			do {
				var relocation = new Relocation(thisReader.readNextUnsignedShort(), thisReader.readNextUnsignedByte(),
						thisReader.readNextUnsignedByte(), thisReader.readNextUnsignedInt());
				
				// Add the relocation's offset to the current module section write address.
				writeAddress += relocation.offset;
				var targetAddress = this.addressSpace.getAddress(writeAddress);
				
				// Set the importing section base address.
				// NOTE: For relocations against the DOL file, the relocation addend will be a physical memory address.
				var importSectionAddress = otherModuleId == 0 ? 0 : otherModule.sections[relocation.section].address & ~1;
				
				switch (relocation.type) {
				case RELProgramBuilder.R_DOLPHIN_END:
					importsFinished = true;
					break;
					
				case RELProgramBuilder.R_DOLPHIN_SECTION:
					writeAddress = thisModule.sections[relocation.section].address & ~1;
					break;
					
				case RELProgramBuilder.R_PPC_ADDR16_HA:
					importSectionAddress += relocation.addend;
					writeValue = (importSectionAddress >> 16) & 0xFFFF;
					if ((importSectionAddress & 0x8000) != 0) {
						writeValue += 1;
					}
					
					programMemory.setShort(targetAddress, (short)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR24:
					writeValue = (importSectionAddress + relocation.addend & 0x3FFFFFC) | 
						(programMemory.getInt(targetAddress) & 0xFC000003);
					
					programMemory.setInt(targetAddress, (int)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR32:
					programMemory.setInt(targetAddress, (int)(importSectionAddress + relocation.addend), true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR16_LO:
					writeValue = (importSectionAddress + relocation.addend) & 0xFFFF;
					
					programMemory.setShort(targetAddress, (short)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR16_HI:
					writeValue = ((importSectionAddress + relocation.addend) >> 16) & 0xFFFF;
					
					programMemory.setShort(targetAddress, (short)writeValue, true);
					
				case RELProgramBuilder.R_PPC_ADDR16:
					writeValue = (importSectionAddress + relocation.addend) & 0xFFFF;
					
					programMemory.setShort(targetAddress, (short)writeValue, true);
					break;
					
				case RELProgramBuilder.R_DOLPHIN_NOP:
				case RELProgramBuilder.R_PPC_NONE:
					break;
					
				case RELProgramBuilder.R_PPC_REL24:
					writeValue = ((importSectionAddress + relocation.addend - writeAddress) & 0x3FFFFFC) |
                        (programMemory.getInt(targetAddress) & 0xFC000003);
					
					programMemory.setInt(targetAddress, (int)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR14:
				case RELProgramBuilder.R_PPC_ADDR14_BRNTAKEN:
				case RELProgramBuilder.R_PPC_ADDR14_BRTAKEN:
					writeValue = ((importSectionAddress + relocation.addend) & 0xFFFC) |
						(programMemory.getInt(targetAddress) & 0xFFFF0003);
					
					programMemory.setInt(targetAddress, (int)writeValue, true);
					break;
				
				case RELProgramBuilder.R_PPC_REL14:
				case RELProgramBuilder.R_PPC_REL14_BRNTAKEN:
				case RELProgramBuilder.R_PPC_REL14_BRTAKEN:
					writeValue = ((importSectionAddress + relocation.addend - writeAddress) & 0xFFFC) |
                    	(programMemory.getInt(targetAddress) & 0xFFFF0003);
				
					programMemory.setInt(targetAddress, (int)writeValue, true);
					break;
					
				default:
					Msg.warn(this, String.format("Relocations: Unsupported relocation %X2", relocation.type));
					break;
				}
				
			} while(importsFinished == false);
		}
		
		return true;
	}
}
