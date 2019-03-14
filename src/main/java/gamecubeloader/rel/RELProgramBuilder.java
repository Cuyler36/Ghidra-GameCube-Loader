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
}
