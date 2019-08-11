package gamecubeloader.dol;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.math.BigInteger;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import gamecubeloader.common.SystemMemorySections;
import gamecubeloader.common.SymbolLoader;
import gamecubeloader.dol.DOLHeader;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.ContextChangeException;
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
	private boolean autoloadMaps;
	private String binaryName;
	
	public DOLProgramBuilder(DOLHeader dol, ByteProvider provider, Program program,
			MemoryConflictHandler memConflictHandler, TaskMonitor monitor, boolean autoloadMaps, boolean createDefaultMemSections) {
		this.dol = dol;
		this.program = program;
		this.memoryBlockUtil = new MemoryBlockUtil(program, memConflictHandler);
		this.autoloadMaps = autoloadMaps;
		this.binaryName = provider.getName();
		
		this.load(monitor, provider);
		if (createDefaultMemSections) {
			SystemMemorySections.Create(program, memoryBlockUtil);
		}
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
					memoryBlockUtil.createInitializedBlock(String.format("MAIN_.text%d", i), addressSpace.getAddress(dol.textSectionMemoryAddresses[i]),
						provider.getInputStream(dol.textSectionOffsets[i]), dol.textSectionSizes[i], "", null, true, true, true, monitor);
					
					if (dol.memoryEndAddress < dol.textSectionMemoryAddresses[i] + dol.textSectionSizes[i]) {
						dol.memoryEndAddress = dol.textSectionMemoryAddresses[i] + dol.textSectionSizes[i];
					}
				}
			}
			
			for (int i = 0; i < 11; i++) {
				if (dol.dataSectionSizes[i] > 0) {
					memoryBlockUtil.createInitializedBlock(String.format("MAIN_.data%d", i), addressSpace.getAddress(dol.dataSectionMemoryAddresses[i]),
						provider.getInputStream(dol.dataSectionOffsets[i]), dol.dataSectionSizes[i], "", null, true, true, false, monitor);
					
					if (dol.memoryEndAddress < dol.dataSectionMemoryAddresses[i] + dol.dataSectionSizes[i]) {
						dol.memoryEndAddress = dol.dataSectionMemoryAddresses[i] + dol.dataSectionSizes[i];
					}
				}
			}
			
			// Add uninitialized sections.
			this.CreateUninitializedSections();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		// Mark the DOL's entry point.
		this.program.getSymbolTable().addExternalEntryPoint(this.addressSpace.getAddress(this.dol.entryPoint));
			
		// Ask if the user wants to load a symbol map file.
		SymbolLoader.LoadMapResult mapLoadedResult = null;
		if (this.autoloadMaps) {
			var name = provider.getName();
			if (name.contains(".")) {
				name = name.substring(0, name.lastIndexOf("."));
			}
			
			mapLoadedResult = SymbolLoader.TryLoadAssociatedMapFile(name, provider.getFile().getParentFile(), this.program, monitor, dol.textSectionMemoryAddresses[0],
					32, dol.bssMemoryAddress);
		}
		
		if (mapLoadedResult != null && mapLoadedResult.loaded == false) {
			if (OptionDialog.showOptionNoCancelDialog(null, "Load Symbols?", "Would you like to load a symbol map for this DOL executable?", "Yes", "No", null) == 1) {
				var fileChooser = new GhidraFileChooser(null);
				fileChooser.setCurrentDirectory(provider.getFile().getParentFile());
				fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
				var selectedFile = fileChooser.getSelectedFile(true);
				
				if (selectedFile != null) {
					FileReader reader = null;
					try {
						reader = new FileReader(selectedFile);
					} catch (FileNotFoundException e) {
						Msg.error(this, String.format("Failed to open the symbol map file!\nReason: %s", e.getMessage()));
					}
					
					if (reader != null) {
						SymbolLoader loader = new SymbolLoader(this.program, monitor, reader, dol.textSectionMemoryAddresses[0], 32, dol.bssMemoryAddress,
							this.binaryName);
						loader.ApplySymbols();
					}
				}
			}
		}
	}
	
	private void CreateUninitializedSections() {
		var uninitializedSectionsSize = dol.bssSize;
		var uninitializedSectionAddress = dol.bssMemoryAddress;
		var uninitializedSectionIdx = 0;
		
		while (uninitializedSectionsSize > 0 && uninitializedSectionIdx < 3) {
			// Check for intersecting sections at the current address + size.
			var uninitializedSectionEndAddress = uninitializedSectionAddress + uninitializedSectionsSize;
			var wroteSection = false;
			
			for (var i = 0; i < this.dol.dataSectionMemoryAddresses.length; i++) {
				var sectionAddress = this.dol.dataSectionMemoryAddresses[i];
				var sectionSize = this.dol.dataSectionSizes[i];
				if (sectionAddress >= uninitializedSectionAddress && sectionAddress < uninitializedSectionEndAddress) {
					// Truncate the size and create a section.
					var thisSectionSize = sectionAddress - uninitializedSectionAddress;
					if (thisSectionSize > 0) {
						var createdSection = memoryBlockUtil.createUninitializedBlock(false, String.format("MAIN_%s", "uninitialized" + uninitializedSectionIdx),
								addressSpace.getAddress(uninitializedSectionAddress), thisSectionSize, "", null, true, true, false);
						
						if (createdSection == null) {
							Msg.warn(this, "Failed to create uninitialized section: " + "uninitialized" + uninitializedSectionIdx);
						}
						
						if (this.dol.memoryEndAddress < uninitializedSectionAddress + thisSectionSize) {
							this.dol.memoryEndAddress = uninitializedSectionAddress + thisSectionSize;
						}
						
						// We also have to subtract any intersecting sections from the size.
						// NOTE: This may not be correct for sections which aren't .sdata & .sdata2 which intersect it.
						uninitializedSectionsSize -= sectionSize;
						
						uninitializedSectionsSize -= thisSectionSize;
						uninitializedSectionAddress = sectionAddress + sectionSize;
						uninitializedSectionIdx++;
						wroteSection = true;
						break;
					}
				}
			}
			
			// If we didn't create any uninitialized sections, we must be clear to write the rest of the size without intersections.
			if (wroteSection == false) {
				var createdSection = memoryBlockUtil.createUninitializedBlock(false, String.format("MAIN_%s", "uninitialized" + uninitializedSectionIdx),
						addressSpace.getAddress(uninitializedSectionAddress), uninitializedSectionsSize, "", null, true, true, false);
				
				if (createdSection == null) {
					Msg.warn(this, "Failed to create uninitialized section: " + DOLHeader.DATA_NAMES[8 + uninitializedSectionIdx]);
				}
				
				if (this.dol.memoryEndAddress < uninitializedSectionAddress + uninitializedSectionsSize) {
					this.dol.memoryEndAddress = uninitializedSectionAddress + uninitializedSectionsSize;
				}
				
				break;
			}
		}
	}
}
