package gamecubeloader.common;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.program.model.listing.Program;

public final class SystemMemorySections {
	public static void Create(Program program) {
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		// Create globals section first
		MemoryBlockUtils.createUninitializedBlock(program, false, "OS Globals", addressSpace.getAddress(0x80000000), 0x3100, "Operating System Globals", null, true, true, false, null);
		
		// Now create hardware registers
		var cp = MemoryBlockUtils.createUninitializedBlock(program, false, "CP", addressSpace.getAddress(0xCC000000), 0x80, "Command Processor Register", null, true, true, false, null);
		cp.setVolatile(true);

		var pe = MemoryBlockUtils.createUninitializedBlock(program, false, "PE", addressSpace.getAddress(0xCC001000), 0x100, "Pixel Engine Register", null, true, true, false, null);
		pe.setVolatile(true);
		
		var vi = MemoryBlockUtils.createUninitializedBlock(program, false, "VI", addressSpace.getAddress(0xCC002000), 0x100, "Video Interface Register", null, true, true, false, null);
		vi.setVolatile(true);
		
		var pi = MemoryBlockUtils.createUninitializedBlock(program, false, "PI", addressSpace.getAddress(0xCC003000), 0x100, "Processor Interface Register", null, true, true, false, null);
		pi.setVolatile(true);
		
		var mi = MemoryBlockUtils.createUninitializedBlock(program, false, "MI", addressSpace.getAddress(0xCC004000), 0x80, "Memory Interface Register", null, true, true, false, null);
		mi.setVolatile(true);
		
		var dsp = MemoryBlockUtils.createUninitializedBlock(program, false, "DSP", addressSpace.getAddress(0xCC005000), 0x200, "Digital Signal Processor Register", null, true, true, false, null);
		dsp.setVolatile(true);
		
		var di = MemoryBlockUtils.createUninitializedBlock(program, false, "DI", addressSpace.getAddress(0xCC006000), 0x40, "DVD Interface Reigster", null, true, true, false, null);
		di.setVolatile(true);
		
		var si = MemoryBlockUtils.createUninitializedBlock(program, false, "SI", addressSpace.getAddress(0xCC006400), 0x100, "Serial Interface Reigster", null, true, true, false, null);
		si.setVolatile(true);
		
		var exi = MemoryBlockUtils.createUninitializedBlock(program, false, "EXI", addressSpace.getAddress(0xCC006800), 0x40, "External Interface Reigster", null, true, true, false, null);
		exi.setVolatile(true);
		
		var ai = MemoryBlockUtils.createUninitializedBlock(program, false, "AI", addressSpace.getAddress(0xCC006C00), 0x40, "Audio Interface Reigster", null, true, true, false, null);
		ai.setVolatile(true);
		
		var gxfifo = MemoryBlockUtils.createUninitializedBlock(program, false, "GXFIFO", addressSpace.getAddress(0xCC008000), 0x8, "Graphics FIFO Reigster", null, true, true, false, null);
		gxfifo.setVolatile(true);
	}
}
