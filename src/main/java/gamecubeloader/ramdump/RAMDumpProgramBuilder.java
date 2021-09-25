package gamecubeloader.ramdump;

import gamecubeloader.common.SystemMemorySections;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class RAMDumpProgramBuilder {
    private long baseAddress;
    private AddressSpace addressSpace;
    private Program program;
    private TaskMonitor monitor;
    
    public RAMDumpProgramBuilder(ByteProvider provider, Program program,
            TaskMonitor monitor, boolean createSystemMemSections, MessageLog log)
                    throws AddressOutOfBoundsException {
        this.program = program;
        this.monitor = monitor;
        
        this.load(provider);
        if (createSystemMemSections) {
            SystemMemorySections.Create(provider, program, monitor, log);
        }
    }
    
    protected void load(ByteProvider provider)
            throws AddressOutOfBoundsException {
        this.baseAddress = 0x80000000L;
        this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        try {
            this.program.setImageBase(addressSpace.getAddress(this.baseAddress), true);
            
            // Create full RAM section.
            MemoryBlockUtils.createInitializedBlock(this.program, false, "RAM", addressSpace.getAddress(this.baseAddress), provider.getInputStream(0),
                    provider.length(), "", null, true, true, true, null, monitor);
            
            // TODO: Support symbol map imports during loading?
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
