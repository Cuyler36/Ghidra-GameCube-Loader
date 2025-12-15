package gamecubeloader.apploader;

import gamecubeloader.common.SystemMemorySections;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;

import java.io.IOException;

public final class ApploaderProgramBuilder {
	public static void load(Program program, Loader.ImporterSettings settings, ApploaderHeader header, boolean createSystemMemSections) throws LoadException {
		var baseAddress = 0x80000000L;
		var provider = settings.provider();
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		try {
			program.setImageBase(addressSpace.getAddress(baseAddress), true);

			// Create Apploader section.
			MemoryBlockUtils.createInitializedBlock(program, false, "Apploader", addressSpace.getAddress(0x81200000L), provider.getInputStream(ApploaderHeader.HEADER_SIZE),
				header.GetSize(), "", null, true, true, true, null, settings.monitor());

			// Create trailer section.
			MemoryBlockUtils.createInitializedBlock(program, false, "Trailer", addressSpace.getAddress(0x81200000L + header.GetSize()),
				provider.getInputStream(ApploaderHeader.HEADER_SIZE + header.GetSize()), header.GetTrailerSize(), "", null, true, true, true, null, settings.monitor());
		} catch (AddressOverflowException | LockException | IOException e) {
			throw new LoadException(e);
		}

		if (createSystemMemSections) {
			SystemMemorySections.Create(provider, program, settings.monitor(), settings.log());
		}
	}
}
