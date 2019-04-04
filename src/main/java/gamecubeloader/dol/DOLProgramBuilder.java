package gamecubeloader.dol;

import java.io.FileReader;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import gamecubeloader.common.SymbolLoader;
import gamecubeloader.dol.DOLHeader;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskMonitor;

public final class DOLProgramBuilder {
	private DOLHeader dol;
	
	private long baseAddress;
	private AddressSpace addressSpace;
	private Program program;
	private MemoryBlockUtil memoryBlockUtil;
	
	public DOLProgramBuilder(DOLHeader dol, ByteProvider provider, Program program,
			MemoryConflictHandler memConflictHandler, TaskMonitor monitor) {
		this.dol = dol;
		this.program = program;
		this.memoryBlockUtil = new MemoryBlockUtil(program, memConflictHandler);
		
		this.load(monitor, provider);
	}
	
	protected void load(TaskMonitor monitor, ByteProvider provider) {
		this.baseAddress = 0x80000000L;
		this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		try {
			this.program.setImageBase(addressSpace.getAddress(this.baseAddress), true);
			dol.memoryEndAddress = 0;
			
			// Load the DOL file.
			for (int i = 0; i < 7; i++) {
				if (dol.textSectionSizes[i] > 0) {
					memoryBlockUtil.createInitializedBlock(DOLHeader.TEXT_NAMES[i], addressSpace.getAddress(dol.textSectionMemoryAddresses[i]),
						provider.getInputStream(dol.textSectionOffsets[i]), dol.textSectionSizes[i], "", null, true, true, true, monitor);
					
					if (dol.memoryEndAddress < dol.textSectionMemoryAddresses[i] + dol.textSectionSizes[i]) {
						dol.memoryEndAddress = dol.textSectionMemoryAddresses[i] + dol.textSectionSizes[i];
					}
				}
			}
			
			for (int i = 0; i < 11; i++) {
				if (dol.dataSectionSizes[i] > 0) {
					memoryBlockUtil.createInitializedBlock(DOLHeader.DATA_NAMES[i], addressSpace.getAddress(dol.dataSectionMemoryAddresses[i]),
						provider.getInputStream(dol.dataSectionOffsets[i]), dol.dataSectionSizes[i], "", null, true, true, false, monitor);
					
					if (dol.memoryEndAddress < dol.dataSectionMemoryAddresses[i] + dol.dataSectionSizes[i]) {
						dol.memoryEndAddress = dol.dataSectionMemoryAddresses[i] + dol.dataSectionSizes[i];
					}
				}
			}
			
			// Add .bss sections.
			var bssSectionSize = dol.dataSectionMemoryAddresses[6] - dol.bssMemoryAddress;
			
			var sdataStartIdx = 6;
			if (dol.dataSectionMemoryAddresses[6] + dol.dataSectionSizes[6] == dol.bssMemoryAddress) {
				bssSectionSize = dol.dataSectionMemoryAddresses[7] - dol.bssMemoryAddress;
				sdataStartIdx = 7;
			}
			
			var bss = memoryBlockUtil.createUninitializedBlock(false, ".bss", addressSpace.getAddress(dol.bssMemoryAddress), bssSectionSize, "", null, true, true, false);
			if (bss == null) {
				Msg.info(this, "bss section creation failed!");
				Msg.info(this, memoryBlockUtil.getMessages());
			}
			else if (dol.memoryEndAddress < dol.bssMemoryAddress + bssSectionSize) {
				dol.memoryEndAddress = dol.bssMemoryAddress + bssSectionSize;
			}
			
			// Check if we need to add a .sbss section.
			if (bssSectionSize + dol.dataSectionSizes[sdataStartIdx] < dol.bssSize) {			
				var sbssSectionAddress = dol.dataSectionMemoryAddresses[sdataStartIdx] + dol.dataSectionSizes[sdataStartIdx];
				var sbssSectionSize = dol.dataSectionMemoryAddresses[sdataStartIdx + 1] - sbssSectionAddress;
				if (dol.dataSectionMemoryAddresses[sdataStartIdx + 1] == 0) {
					sbssSectionSize = dol.bssSize - (bssSectionSize + dol.dataSectionSizes[6] + dol.dataSectionSizes[7]); // Fallback?
				}
				
				var sbss = memoryBlockUtil.createUninitializedBlock(false, ".sbss", addressSpace.getAddress(sbssSectionAddress), sbssSectionSize, "", null, true, true, false);
				if (sbss == null) {
					Msg.info(this, "sbss section creation failed!");
					Msg.info(this, memoryBlockUtil.getMessages());
				}
				else if (dol.memoryEndAddress < sbssSectionAddress + sbssSectionSize) {
					dol.memoryEndAddress = sbssSectionAddress + sbssSectionSize;
				}
				
				// TODO: .sdata2 & .sbss2 are odd. They're not included in the uninitialized sections size in AC, but .sdata2 does exist. How is this handled?
				var sdata2StartIdx = sdataStartIdx + 1;
				if (bssSectionSize + dol.dataSectionSizes[sdataStartIdx] + sbssSectionSize + dol.dataSectionSizes[sdata2StartIdx] < dol.bssSize) {
					var sbss2Address = dol.dataSectionMemoryAddresses[sdata2StartIdx] + dol.dataSectionSizes[sdata2StartIdx];
					var sbss2SectionSize = dol.bssSize - (bssSectionSize + dol.dataSectionSizes[sdataStartIdx] + sbssSectionSize + dol.dataSectionSizes[sdata2StartIdx]);
					
					if (sbss2SectionSize > 0) {
						var sbss2 = memoryBlockUtil.createUninitializedBlock(false, ".sbss2", addressSpace.getAddress(sbss2Address), sbss2SectionSize, "", null, true, true, false);
						if (sbss2 == null) {
							Msg.info(this, "sbss2 section creation failed!");
							Msg.info(this,  memoryBlockUtil.getMessages());
						}
						else if (dol.memoryEndAddress < sbss2Address + sbss2SectionSize) {
							dol.memoryEndAddress = sbss2Address + sbss2SectionSize;
						}
					}
				}
			}
			
			// Ask if the user wants to load a symbol map file.
			if (OptionDialog.showOptionNoCancelDialog(null, "Load Symbols?", "Would you like to load a symbol map for this DOL executable?", "Yes", "No", null) == 1) {
				var fileChooser = new GhidraFileChooser(null);
				fileChooser.setCurrentDirectory(provider.getFile().getParentFile());
				fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
				var selectedFile = fileChooser.getSelectedFile(true);
				
				if (selectedFile != null) {
					FileReader reader = new FileReader(selectedFile);
					SymbolLoader loader = new SymbolLoader(this.program, monitor, reader, dol.textSectionMemoryAddresses[0], 32, dol.bssMemoryAddress);
					loader.ApplySymbols();
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	

}
