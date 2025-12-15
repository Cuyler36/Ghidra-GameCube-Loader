package gamecubeloader.dol;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import gamecubeloader.common.SymbolLoader;
import gamecubeloader.common.SystemMemorySections;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public final class DOLProgramBuilder {
	public static void load(Program program, Loader.ImporterSettings settings, DOLHeader dol, boolean autoloadMaps, boolean createDefaultMemSections) throws LoadException {
		var baseAddress = 0x80000000L;
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		var provider = settings.provider();

		try {
			program.setImageBase(addressSpace.getAddress(baseAddress), true);
			dol.memoryEndAddress = 0;

			// Load the DOL file.
			for (int i = 0; i < 7; i++) {
				if (dol.textSectionSizes[i] > 0) {
					MemoryBlockUtils.createInitializedBlock(program, false, String.format("MAIN_.text%d", i), addressSpace.getAddress(dol.textSectionMemoryAddresses[i]),
						provider.getInputStream(dol.textSectionOffsets[i]), dol.textSectionSizes[i], "", null, true, true, true, null, settings.monitor());

					if (dol.memoryEndAddress < dol.textSectionMemoryAddresses[i] + dol.textSectionSizes[i]) {
						dol.memoryEndAddress = dol.textSectionMemoryAddresses[i] + dol.textSectionSizes[i];
					}
				}
			}

			for (int i = 0; i < 11; i++) {
				if (dol.dataSectionSizes[i] > 0) {
					MemoryBlockUtils.createInitializedBlock(program, false, String.format("MAIN_.data%d", i), addressSpace.getAddress(dol.dataSectionMemoryAddresses[i]),
						provider.getInputStream(dol.dataSectionOffsets[i]), dol.dataSectionSizes[i], "", null, true, true, false, null, settings.monitor());

					if (dol.memoryEndAddress < dol.dataSectionMemoryAddresses[i] + dol.dataSectionSizes[i]) {
						dol.memoryEndAddress = dol.dataSectionMemoryAddresses[i] + dol.dataSectionSizes[i];
					}
				}
			}

			// Add uninitialized sections.
			createUninitializedSections(program, dol);
		} catch (IOException | AddressOverflowException | LockException e) {
			throw new LoadException(e);
		}

		// Mark the DOL's entry point.
		program.getSymbolTable().addExternalEntryPoint(addressSpace.getAddress(dol.entryPoint));

		// Ask if the user wants to load a symbol map file.
		SymbolLoader.LoadMapResult mapLoadedResult = null;
		if (autoloadMaps) {
			var name = provider.getName();
			if (name.contains(".")) {
				name = name.substring(0, name.lastIndexOf("."));
			}

			mapLoadedResult = SymbolLoader.TryLoadAssociatedMapFile(name, provider.getFile().getParentFile(), program, settings.monitor(), dol.textSectionMemoryAddresses[0],
				32, dol.bssMemoryAddress);
		}

		if (mapLoadedResult != null && !mapLoadedResult.loaded) {
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
						Msg.error(DOLProgramBuilder.class, String.format("Failed to open the symbol map file!\nReason: %s", e.getMessage()));
					}

					if (reader != null) {
						SymbolLoader loader = new SymbolLoader(program, settings.monitor(), reader, dol.textSectionMemoryAddresses[0], 32, dol.bssMemoryAddress,
							provider.getName(), true);
						loader.ApplySymbols();
					}
				}
			}
		}

		if (createDefaultMemSections) {
			SystemMemorySections.Create(provider, program, settings.monitor(), settings.log());
		}
	}

	private static void createUninitializedSections(Program program, DOLHeader dol) {
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		var uninitializedSectionsSize = dol.bssSize;
		var uninitializedSectionAddress = dol.bssMemoryAddress;
		var uninitializedSectionIdx = 0;

		while (uninitializedSectionsSize > 0 && uninitializedSectionIdx < 3) {
			// Check for intersecting sections at the current address + size.
			var uninitializedSectionEndAddress = uninitializedSectionAddress + uninitializedSectionsSize;
			var wroteSection = false;

			for (var i = 0; i < dol.dataSectionMemoryAddresses.length; i++) {
				var sectionAddress = dol.dataSectionMemoryAddresses[i];
				var sectionSize = dol.dataSectionSizes[i];
				if (sectionAddress >= uninitializedSectionAddress && sectionAddress < uninitializedSectionEndAddress) {
					// Truncate the size and create a section.
					var thisSectionSize = sectionAddress - uninitializedSectionAddress;
					if (thisSectionSize > 0) {
						var createdSection = MemoryBlockUtils.createUninitializedBlock(program, false, String.format("MAIN_%s", "uninitialized" + uninitializedSectionIdx),
							addressSpace.getAddress(uninitializedSectionAddress), thisSectionSize, "", null, true, true, false, null);

						if (createdSection == null) {
							Msg.warn(DOLProgramBuilder.class, "Failed to create uninitialized section: " + "uninitialized" + uninitializedSectionIdx);
						}

						if (dol.memoryEndAddress < uninitializedSectionAddress + thisSectionSize) {
							dol.memoryEndAddress = uninitializedSectionAddress + thisSectionSize;
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
			if (!wroteSection) {
				var createdSection = MemoryBlockUtils.createUninitializedBlock(program, false, String.format("MAIN_%s", "uninitialized" + uninitializedSectionIdx),
					addressSpace.getAddress(uninitializedSectionAddress), uninitializedSectionsSize, "", null, true, true, false, null);

				if (createdSection == null) {
					Msg.warn(DOLProgramBuilder.class, "Failed to create uninitialized section: " + DOLHeader.DATA_NAMES[8 + uninitializedSectionIdx]);
				}

				if (dol.memoryEndAddress < uninitializedSectionAddress + uninitializedSectionsSize) {
					dol.memoryEndAddress = uninitializedSectionAddress + uninitializedSectionsSize;
				}

				break;
			}
		}
	}
}
