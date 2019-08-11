package gamecubeloader.apploader;

import gamecubeloader.common.SystemMemorySections;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class ApploaderProgramBuilder {
	private ApploaderHeader header;
	
	private long baseAddress;
	private AddressSpace addressSpace;
	private Program program;
	private MemoryBlockUtil memoryBlockUtil;
	private TaskMonitor monitor;
	
	public ApploaderProgramBuilder(ApploaderHeader header, ByteProvider provider, Program program,
			MemoryConflictHandler memConflictHandler, TaskMonitor monitor, boolean createSystemMemSections)
					throws AddressOutOfBoundsException {
		this.header = header;
		
		this.program = program;
		this.memoryBlockUtil = new MemoryBlockUtil(program, memConflictHandler);
		this.monitor = monitor;
		
		this.load(provider);
		if (createSystemMemSections) {
			SystemMemorySections.Create(program, memoryBlockUtil);
		}
	}
	
	protected void load(ByteProvider provider)
			throws AddressOutOfBoundsException {
		this.baseAddress = 0x80000000L;
		this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		try {
			this.program.setImageBase(addressSpace.getAddress(this.baseAddress), true);
			
			// Create Apploader section.
			memoryBlockUtil.createInitializedBlock("Apploader", addressSpace.getAddress(0x81200000), provider.getInputStream(ApploaderHeader.HEADER_SIZE),
					header.GetSize(), "", null, true, true, true, monitor);
			
			// Create trailer section.
			memoryBlockUtil.createInitializedBlock("Trailer", addressSpace.getAddress(0x81200000 + header.GetSize()),
					provider.getInputStream(ApploaderHeader.HEADER_SIZE + header.GetSize()), header.GetTrailerSize(), "", null, true, true, true, monitor);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
