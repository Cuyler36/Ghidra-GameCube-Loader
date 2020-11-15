package gamecubeloader.apploader;

import gamecubeloader.common.SystemMemorySections;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class ApploaderProgramBuilder {
	private ApploaderHeader header;
	
	private long baseAddress;
	private AddressSpace addressSpace;
	private Program program;
	private TaskMonitor monitor;
	
	public ApploaderProgramBuilder(ApploaderHeader header, ByteProvider provider, Program program,
			TaskMonitor monitor, boolean createSystemMemSections, MessageLog log)
					throws AddressOutOfBoundsException {
		this.header = header;
		
		this.program = program;
		this.monitor = monitor;
		
		this.load(provider);
		if (createSystemMemSections) {
			SystemMemorySections.Create(program, log);
		}
	}
	
	protected void load(ByteProvider provider)
			throws AddressOutOfBoundsException {
		this.baseAddress = 0x80000000L;
		this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		try {
			this.program.setImageBase(addressSpace.getAddress(this.baseAddress), true);
			
			// Create Apploader section.
			MemoryBlockUtils.createInitializedBlock(this.program, false, "Apploader", addressSpace.getAddress(0x81200000), provider.getInputStream(ApploaderHeader.HEADER_SIZE),
					header.GetSize(), "", null, true, true, true, null, monitor);
			
			// Create trailer section.
			MemoryBlockUtils.createInitializedBlock(this.program, false, "Trailer", addressSpace.getAddress(0x81200000 + header.GetSize()),
					provider.getInputStream(ApploaderHeader.HEADER_SIZE + header.GetSize()), header.GetTrailerSize(), "", null, true, true, true, null, monitor);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
