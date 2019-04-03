package gamecubeloader.rel;

import java.io.IOException;
import java.util.*;

import gamecubeloader.dol.DOLHeader;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class RELProgramBuilder  {
	private RELHeader rel;
	private List<ByteProvider> relProviders;
	private List<BinaryReader> relMemoryReaders;
	
	private long baseAddress;
	private AddressSpace addressSpace;
	private Program program;
	private MemoryBlockUtil memoryBlockUtil;
	
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
	
	protected RELProgramBuilder(RELHeader rel, ByteProvider provider, Program program,
			MemoryConflictHandler memConflictHandler) {
		// TODO: Search the directory for any other REL & DOL files.
		
		this.rel = rel;
		this.program = program;
		this.memoryBlockUtil = new MemoryBlockUtil(program, memConflictHandler);
	}
	
	protected void load(TaskMonitor monitor, List<Long> addresses) {
		this.baseAddress = 0x80000000;
		this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		try {
			this.program.setImageBase(addressSpace.getAddress(this.baseAddress), true);
			//this.loadDefaultSegments(monitor);
			relMemoryReaders = new ArrayList<BinaryReader>();
			for (ByteProvider provider : relProviders) {
				relMemoryReaders.add(new BinaryReader(provider, true));
			}
			
			
		}
		catch (Exception e) {
			
		}
	}
	
	private List<Long> DetermineFileBaseAddresses(List<RELHeader> rels, List<ByteProvider> providers,
			DOLHeader dol, ByteProvider dolProvider) {
		List<Long> fileAddresses = new ArrayList<Long>();
		// Use the DOL text section 0 as the base address if one exists. If not, default to 0x80001000.
		long address = dol != null ? dol.textSectionMemoryAddresses[0] : 0x80001000;
		
		if (dol != null) {
			fileAddresses.add(address);
			
			try {
				address += dolProvider.length() - DOLHeader.SIZE;
			}
			catch (IOException e) {
				Msg.error(this, "Failed to get the length of the DOL file. Size will be calculated based on the memory & data sizes.");
				for (long size : dol.textSectionSizes) {
					// Check if alignment is needed. 32 bytes is the alignment size?
					if ((size & 0x1F) != 0) {
						address += size + 32 - size & 0x1F;
					}
				}
				
				for (long size : dol.dataSectionSizes) {
					// Check if alignment is needed. 32 bytes is the alignment size?
					if ((size & 0x1F) != 0) {
						address += size + 32 - size & 0x1F;
					}
				}
			}
			
			// Add .bss section into the size since the DOL bss will always immediately follow the file.
			address += dol.bssSize;
			if ((address & 0x1F) != 0) {
				address += 32 - address & 0x1F;
			}
		}
		
		for (ByteProvider provider : providers) {
			// The entire REL file is loaded into RAM (including the header), so just add it.
			fileAddresses.add(address);
			
			try {
				address += provider.length();
			}
			catch (IOException e) {
				Msg.error(this, "An error occurred while loading a REL file. A default size of 0x1000000 will be used.");
				address += 0x01000000;
			}
		}
		
		return fileAddresses;
	}
	
	private boolean Relocate(RELHeader otherModule, RELHeader thisModule, BinaryReader thisReader)
			throws IOException, MemoryAccessException {
		var otherModuleId = otherModule == null ? 0 : otherModule.moduleId;
		
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
				var importSectionAddress = otherModule.sections[relocation.section].address & ~1;
				
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
					
					this.program.getMemory().setShort(targetAddress, (short)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR24:
					writeValue = (importSectionAddress + relocation.addend & 0x3FFFFFC) | 
						(thisReader.readUnsignedInt(writeAddress) & 0xFC000003);
					
					this.program.getMemory().setInt(targetAddress, (int)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR32:
					this.program.getMemory().setInt(targetAddress, (int)(importSectionAddress + relocation.addend), true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR16_LO:
					writeValue = (importSectionAddress + relocation.addend) & 0xFFFF;
					
					this.program.getMemory().setShort(targetAddress, (short)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR16_HI:
					writeValue = ((importSectionAddress + relocation.addend) >> 16) & 0xFFFF;
					
					this.program.getMemory().setShort(targetAddress, (short)writeValue, true);
					
				case RELProgramBuilder.R_PPC_ADDR16:
					writeValue = (importSectionAddress + relocation.addend) & 0xFFFF;
					
					this.program.getMemory().setShort(targetAddress, (short)writeValue, true);
					break;
					
				case RELProgramBuilder.R_DOLPHIN_NOP:
				case RELProgramBuilder.R_PPC_NONE:
					break;
					
				case RELProgramBuilder.R_PPC_REL24:
					writeValue = ((importSectionAddress + relocation.addend - writeAddress) & 0x3FFFFFC) |
                        (thisReader.readUnsignedInt(writeAddress) & 0xFC000003);
					
					this.program.getMemory().setInt(targetAddress, (int)writeValue, true);
					break;
					
				case RELProgramBuilder.R_PPC_ADDR14:
				case RELProgramBuilder.R_PPC_ADDR14_BRNTAKEN:
				case RELProgramBuilder.R_PPC_ADDR14_BRTAKEN:
					writeValue = ((importSectionAddress + relocation.addend) & 0xFFFC) |
						(thisReader.readUnsignedInt(writeAddress) & 0xFFFF0003);
					
					this.program.getMemory().setInt(targetAddress, (int)writeValue, true);
					break;
				
				case RELProgramBuilder.R_PPC_REL14:
				case RELProgramBuilder.R_PPC_REL14_BRNTAKEN:
				case RELProgramBuilder.R_PPC_REL14_BRTAKEN:
					writeValue = ((importSectionAddress + relocation.addend - writeAddress) & 0xFFFC) |
                    	(thisReader.readUnsignedInt(writeAddress) & 0xFFFF0003);
				
					this.program.getMemory().setInt(targetAddress, (int)writeValue, true);
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
