package gamecubeloader.rel;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import gamecubeloader.common.SymbolInfo;
import gamecubeloader.common.SymbolLoader;
import gamecubeloader.common.SystemMemorySections;
import gamecubeloader.common.Yaz0;
import gamecubeloader.dol.DOLHeader;
import gamecubeloader.dol.DOLProgramBuilder;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import org.apache.commons.io.FilenameUtils;
import org.python.google.common.primitives.Ints;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.*;

public final class RELProgramBuilder {
	private static final long EXECUTABLE_SECTION = 1;

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
	private static final short R_DOLPHIN_MRKREF = 204;

	private static final class ImportEntry {
		public long moduleId;
		public long offset;

		public ImportEntry(long moduleId, long offset) {
			this.moduleId = moduleId;
			this.offset = offset;
		}
	}

	private static final class Relocation {
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

	private static final class RelocatableModuleInfo {
		public RELHeader header;
		public BinaryReader reader;
		public String name;

		public RelocatableModuleInfo(RELHeader header, BinaryReader reader, String name) {
			this.header = header;
			this.reader = reader;
			this.name = name;
		}
	}

	public static void load(Program program, Loader.ImporterSettings settings, RELHeader rel, boolean autoloadMaps, boolean saveRelocations,
							boolean createDefaultMemSections, boolean specifyModuleMemAddrs)
		throws LoadException {
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		var provider = settings.provider();
		try {
			Yaz0 yaz0 = new Yaz0();
			if (yaz0.IsValid(provider)) {
				provider = yaz0.Decompress(provider);
			}
		} catch (IOException e) {
			throw new LoadException("Failed to decompress Yaz0", e);
		}

		var originalFile = provider.getFile();
		var relArray = new ArrayList<RelocatableModuleInfo>();
		relArray.add(new RelocatableModuleInfo(rel, new BinaryReader(provider, false), FilenameUtils.getBaseName(originalFile.getName())));

		DOLHeader dol = null;
		BinaryReader dolReader = null;

		var directory = originalFile.getParentFile();
		for (File file : Objects.requireNonNull(directory.listFiles())) {
			var fileName = file.getName();

			if (fileName.equals(originalFile.getName())) continue;

			try {
				if (fileName.endsWith(".dol")) {
					var dolProvider = new FileByteProvider(file, null, AccessMode.READ);
					var dol_reader = new BinaryReader(dolProvider, false);
					var dolHeader = new DOLHeader(dol_reader);

					if (dolHeader.CheckHeaderIsValid()) {
						dol = dolHeader;
						dolReader = dol_reader;
					}
				} else if (fileName.endsWith(".rel") || fileName.endsWith(".szs") || fileName.endsWith(".yaz0")) {
					ByteProvider relProvider = new FileByteProvider(file, null, AccessMode.READ);
					var relReader = new BinaryReader(relProvider, false);

					var yaz0 = new Yaz0();
					if (yaz0.IsValid(relProvider)) {
						relProvider = yaz0.Decompress(relProvider);
						relReader = new BinaryReader(relProvider, false);
					}

					var relHeader = new RELHeader(relReader);
					if (relHeader.IsValid(relReader)) {
						// Verify no other modules with the same module id exist before loading.
						var invalid = false;
						for (RelocatableModuleInfo info : relArray) {
							if (info.header.moduleId == relHeader.moduleId) {
								invalid = true;
								break;
							}
						}

						if (!invalid) {
							relArray.add(new RelocatableModuleInfo(relHeader, relReader, FilenameUtils.getBaseName(file.getName())));
						} else {
							relProvider.close();
						}
					} else {
						relProvider.close();
					}
				}
			} catch (IOException e) {
				throw new LoadException(String.format("Failed to process file %s", originalFile.getName()), e);
			}
		}

		var currentOutputAddress = 0x80000000L;

		// If a DOL file exists, load it first.
		if (dol != null) {
			var dolSettings = new Loader.ImporterSettings(
				dolReader.getByteProvider(),
				dolReader.getByteProvider().getName(),
				settings.project(),
				settings.projectRootPath(),
				settings.mirrorFsLayout(),
				settings.loadSpec(),
				settings.options(),
				settings.consumer(),
				settings.log(),
				settings.monitor()
			);
			DOLProgramBuilder.load(program, dolSettings, dol, autoloadMaps, false);
			currentOutputAddress = align(dol.memoryEndAddress, 0x20);
		}

		// Load all rel files based on their module id.
		relArray.sort(Comparator.comparingLong(info -> info.header.moduleId)); // Sort rel headers based on their module ids.
		var relBaseAddress = 0L;

		List<Map<Long, SymbolInfo>> symbolInfoList = new ArrayList<>();
		for (RelocatableModuleInfo relInfo : relArray) {
			relInfo.header.bssSectionId = 0;
			relBaseAddress = currentOutputAddress;

			// If we're using manually specified memory addresses, ask the user where they want this file to be loaded.
			if (specifyModuleMemAddrs) {
				// TODO: Check against addresses already containing memory sections.
				var setValidAddress = false;
				while (!setValidAddress) {
					var selectedAddress = OptionDialog.showInputSingleLineDialog(null, "Specify Memory Address", "Specify the base memory address for Module " +
						relInfo.name, Long.toHexString(relBaseAddress));

					if (selectedAddress == null) {
						break; // The user selected the cancel dialog.
					}

					try {
						var specifiedAddr = Long.parseUnsignedLong(selectedAddress, 16);
						if (specifiedAddr >= 0x80000000L && (specifiedAddr + relInfo.header.Size()) < 0x81800000L) {
							relBaseAddress = currentOutputAddress = specifiedAddr;
							setValidAddress = true;
						}
					} catch (NumberFormatException e) {
						continue;
					}
				}
			}

			var textCount = 0;
			var dataCount = 0;
			for (var s = 0; s < relInfo.header.sectionCount; s++) {
				var section = relInfo.header.sections[s];
				if (section.size != 0) {
					if (section.address != 0) {
						var isText = (section.address & RELProgramBuilder.EXECUTABLE_SECTION) != 0;
						var blockName = String.format("%s_%s%d", relInfo.name, isText ? ".text" : ".data", isText ? textCount : dataCount);

						// Update the address of the section with its virtual memory address.
						var offs = section.address & ~1;
						section.address = relBaseAddress + offs;

						try {
							var stream = relInfo.reader.getByteProvider().getInputStream(offs);
							MemoryBlockUtils.createInitializedBlock(program, false, blockName, addressSpace.getAddress(section.address),
								stream, section.size, "", null, true, true, isText, null, settings.monitor());
						} catch (IOException | AddressOverflowException e) {
							throw new LoadException(String.format("Failed to create memory block %s for module %s", blockName, relInfo.name), e);
						}

						if (isText) textCount++;
						else dataCount++;

						currentOutputAddress = section.address + section.size;

						// Ensure output address is aligned to 4 bytes
						if ((currentOutputAddress & 3) != 0) {
							currentOutputAddress = (currentOutputAddress + 4) & ~3;
						}
					} else if (relInfo.header.bssSectionId == 0) {
						relInfo.header.bssSectionId = s;
					}
				}
			}

			// Add bss section.
			if (relInfo.header.bssSize != 0 && relInfo.header.bssSectionId != 0) {
				if (specifyModuleMemAddrs) {
					// TODO: Check against addresses already containing memory sections.
					var setValidAddress = false;
					while (!setValidAddress) {
						var selectedAddress = OptionDialog.showInputSingleLineDialog(null, "Specify BSS Address", "Specify the BSS memory address for Module " +
							relInfo.name, Long.toHexString(currentOutputAddress));

						if (selectedAddress == null) {
							break;
						}

						try {
							var specifiedAddr = Long.parseUnsignedLong(selectedAddress, 16);
							if (specifiedAddr >= 0x80000000L && (specifiedAddr + relInfo.header.Size()) < 0x81800000L) {
								currentOutputAddress = specifiedAddr;
								setValidAddress = true;
							}
						} catch (NumberFormatException e) {
							continue;
						}
					}
				} else if (relInfo.header.moduleVersion < 2 || relInfo.header.bssSectionAlignment == 0) {
					currentOutputAddress = align(currentOutputAddress, 0x20);
				} else {
					currentOutputAddress = align(currentOutputAddress, (int) relInfo.header.bssSectionAlignment);
				}

				MemoryBlockUtils.createUninitializedBlock(program, false, relInfo.name + "_.uninitialized0", addressSpace.getAddress(currentOutputAddress), relInfo.header.bssSize,
					"", null, true, true, false, null);

				// Set the bss virtual memory address.
				relInfo.header.sections[relInfo.header.bssSectionId].address = currentOutputAddress;

				currentOutputAddress += relInfo.header.bssSize;
			}

			// Mark the Relocatable Module's prolog, epilog, & unresolved functions as external entry points.
			var symbolTable = program.getSymbolTable();
			if (relInfo.header.prologSectionId != 0) {
				var prologAddress = (relInfo.header.prologSectionOffset + relInfo.header.sections[relInfo.header.prologSectionId].address) & ~RELProgramBuilder.EXECUTABLE_SECTION;
				symbolTable.addExternalEntryPoint(addressSpace.getAddress(prologAddress));
			}

			if (relInfo.header.unresolvedSectionId != 0) {
				var unresolvedAddress = (relInfo.header.unresolvedSectionOffset + relInfo.header.sections[relInfo.header.unresolvedSectionId].address) & ~RELProgramBuilder.EXECUTABLE_SECTION;
				symbolTable.addExternalEntryPoint(addressSpace.getAddress(unresolvedAddress));
			}

			if (relInfo.header.epilogSectionId != 0) {
				var epilogAddress = (relInfo.header.epilogSectionOffset + relInfo.header.sections[relInfo.header.epilogSectionId].address) & ~RELProgramBuilder.EXECUTABLE_SECTION;
				symbolTable.addExternalEntryPoint(addressSpace.getAddress(epilogAddress));
			}

			// Align the output address for the next module.
			currentOutputAddress = align(currentOutputAddress, 0x20);

			SymbolLoader.LoadMapResult mapLoadedResult = null;
			if (autoloadMaps) {
				var name = relInfo.name;
				if (name.contains(".")) {
					name = name.substring(0, name.lastIndexOf("."));
				}

				mapLoadedResult = SymbolLoader.TryLoadAssociatedMapFile(name, directory, program, settings.monitor(), relBaseAddress + relInfo.header.FullSize(), (int) relInfo.header.sectionAlignment,
					relInfo.header.bssSectionId != 0 ? relInfo.header.sections[relInfo.header.bssSectionId].address : 0);

				if (mapLoadedResult.loaded) {
					symbolInfoList.add(mapLoadedResult.symbolMap);
				}
			}

			if (mapLoadedResult != null && !mapLoadedResult.loaded) {
				// Ask if the user wants to load a symbol map file.
				if (OptionDialog.showOptionNoCancelDialog(null, "Load Symbols?", String.format("Would you like to load a symbol map for the relocatable module %s?", relInfo.name),
					"Yes", "No", null) == 1) {
					var fileChooser = new GhidraFileChooser(null);
					fileChooser.setCurrentDirectory(originalFile.getParentFile());
					fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
					var selectedFile = fileChooser.getSelectedFile(true);

					if (selectedFile != null) {
						try {
							var reader = new FileReader(selectedFile);
							var loader = new SymbolLoader(program, settings.monitor(), reader, relBaseAddress + relInfo.header.FullSize(), 0,
								relInfo.header.bssSectionId != 0 ? relInfo.header.sections[relInfo.header.bssSectionId].address : 0,
								provider.getName(), true);
							symbolInfoList.add(loader.ApplySymbols());
						} catch (IOException e) {
							throw new LoadException(String.format("Error while processing symbol map file %s", selectedFile.getAbsolutePath()), e);
						}
					}
				}
			}
		}

		// Apply relocations.
		for (var relIdx = 0; relIdx < relArray.size(); relIdx++) {
			var thisRel = relArray.get(relIdx);

			// Set the symbol info map for the current module.
			Map<Long, SymbolInfo> symbolInfo = null;
			if (relIdx < symbolInfoList.size()) {
				symbolInfo = symbolInfoList.get(relIdx);
			}

			// Do relocations against the DOL file first if it exists.
			if (dol != null) {
				try {
					relocate(program, null, thisRel.header, thisRel.reader, symbolInfo, saveRelocations);
				} catch (IOException | MemoryAccessException e) {
					throw new LoadException(String.format("Error relocating REL %s against DOL", thisRel.name), e);
				}
			}

			// Now do relocations against modules.
			for (RelocatableModuleInfo otherRel : relArray) {
				try {
					relocate(program, otherRel.header, thisRel.header, thisRel.reader, symbolInfo, saveRelocations);
				} catch (IOException | MemoryAccessException e) {
					throw new LoadException(String.format("Error relocating REL %s against REL %s", thisRel.name, otherRel.name), e);
				}
			}
		}

		if (createDefaultMemSections) {
			SystemMemorySections.Create(provider, program, settings.monitor(), settings.log());
		}
	}

	private static long align(long address, int alignment) {
		var inverse = alignment - 1;
		if ((address & inverse) != 0) {
			address = (address + inverse) & ~inverse;
		}

		return address;
	}

	private static void relocate(Program program, RELHeader otherModule, RELHeader thisModule, BinaryReader thisReader, Map<Long, SymbolInfo> symbolInfo, boolean saveRelocations)
		throws IOException, MemoryAccessException {
		var baseAddress = 0x80000000L;
		var otherModuleId = otherModule == null ? 0 : otherModule.moduleId;
		var programMemory = program.getMemory();
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		var importTableEntryCount = (int) (thisModule.importTableSize / RELProgramBuilder.IMPORT_ENTRY_SIZE);
		var importEntries = new ImportEntry[importTableEntryCount];

		// Seek to the import table.
		thisReader.setPointerIndex(thisModule.importTableOffset);

		// Load import entries.
		for (var i = 0; i < importTableEntryCount; i++) {
			importEntries[i] = new ImportEntry(thisReader.readNextUnsignedInt(), thisReader.readNextUnsignedInt());
		}

		// Begin relocations.
		for (ImportEntry entry : importEntries) {
			// Skip any entries that aren't imports from the "otherModule".
			if (entry.moduleId != otherModuleId) continue;

			Msg.info(RELProgramBuilder.class, String.format("Relocations: Starting relocations for module %d from module %d", thisModule.moduleId, otherModuleId));

			// Seek to the beginning of this entry's relocation data.
			thisReader.setPointerIndex(entry.offset);

			// Begin applying relocations.
			var importsFinished = false;
			var writeAddress = 0L;
			var writeValue = 0L;

			do {
				var relocation = new Relocation(thisReader.readNextUnsignedShort(), thisReader.readNextUnsignedByte(),
					thisReader.readNextUnsignedByte(), thisReader.readNextUnsignedInt());

				// Add the relocation's offset to the current module section write address.
				writeAddress += relocation.offset;
				var targetAddress = addressSpace.getAddress(writeAddress);
				var inBounds = saveRelocations && writeAddress >= baseAddress && writeAddress < baseAddress + 0x01800000;

				// Store the original value at the target address.
				var originalValue = -1;
				if (inBounds) {
					try {
						originalValue = programMemory.getInt(targetAddress, true);
					} catch (Exception e) {
						inBounds = false;
					}
				}

				// Set the importing section base address.
				// NOTE: For relocations against the DOL file, the relocation addend will be a physical memory address.
				var importSectionAddress = otherModuleId == 0 ? 0 : otherModule.sections[relocation.section].address & ~1;

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

						programMemory.setShort(targetAddress, (short) writeValue, true);
						break;

					case RELProgramBuilder.R_PPC_ADDR24:
						writeValue = (importSectionAddress + relocation.addend & 0x3FFFFFC) |
							(programMemory.getInt(targetAddress) & 0xFC000003);

						programMemory.setInt(targetAddress, (int) writeValue, true);
						break;

					case RELProgramBuilder.R_PPC_ADDR32:
						programMemory.setInt(targetAddress, (int) (importSectionAddress + relocation.addend), true);
						break;

					case RELProgramBuilder.R_PPC_ADDR16:
					case RELProgramBuilder.R_PPC_ADDR16_LO:
						writeValue = (importSectionAddress + relocation.addend) & 0xFFFF;

						programMemory.setShort(targetAddress, (short) writeValue, true);
						break;

					case RELProgramBuilder.R_PPC_ADDR16_HI:
						writeValue = ((importSectionAddress + relocation.addend) >> 16) & 0xFFFF;

						programMemory.setShort(targetAddress, (short) writeValue, true);
						break;

					case RELProgramBuilder.R_DOLPHIN_NOP:
					case RELProgramBuilder.R_PPC_NONE:
						break;

					case RELProgramBuilder.R_PPC_REL24:
						writeValue = ((importSectionAddress + relocation.addend - writeAddress) & 0x3FFFFFC) |
							(programMemory.getInt(targetAddress) & 0xFC000003);

						programMemory.setInt(targetAddress, (int) writeValue, true);
						break;

					case RELProgramBuilder.R_PPC_ADDR14:
					case RELProgramBuilder.R_PPC_ADDR14_BRNTAKEN:
					case RELProgramBuilder.R_PPC_ADDR14_BRTAKEN:
						writeValue = ((importSectionAddress + relocation.addend) & 0xFFFC) |
							(programMemory.getInt(targetAddress) & 0xFFFF0003);

						programMemory.setInt(targetAddress, (int) writeValue, true);
						break;

					case RELProgramBuilder.R_PPC_REL14:
					case RELProgramBuilder.R_PPC_REL14_BRNTAKEN:
					case RELProgramBuilder.R_PPC_REL14_BRTAKEN:
						writeValue = ((importSectionAddress + relocation.addend - writeAddress) & 0xFFFC) |
							(programMemory.getInt(targetAddress) & 0xFFFF0003);

						programMemory.setInt(targetAddress, (int) writeValue, true);
						break;

					default:
						Msg.warn(RELProgramBuilder.class, String.format("Relocations: Unsupported relocation %X", relocation.type));
						break;
				}

				// Add the relocation to Ghidra's relocation table view.
				if (inBounds) {
					long newValue = programMemory.getInt(targetAddress, true) & 0xFFFFFFFFL;
					if (newValue != (originalValue & 0xFFFFFFFFL)) {
						var symbolName = "";
						Symbol symbol = null;

						if (symbolInfo != null) {
							if (symbolInfo.containsKey(writeAddress)) {
								symbol = program.getSymbolTable().getPrimarySymbol(targetAddress);
							} else {
								// Search symbols for an overlapping symbol. TODO: This is slow. Think of a better way.
								for (SymbolInfo info : symbolInfo.values()) {
									if (writeAddress >= info.virtualAddress && writeAddress < info.virtualAddress + info.size) {
										symbol = program.getSymbolTable().getPrimarySymbol(addressSpace.getAddress(info.virtualAddress));
										break;
									}
								}
							}
						}

						if (symbol != null) {
							symbolName = symbol.getName();
						}

						program.getRelocationTable().add(targetAddress, Status.APPLIED, relocation.type, new long[]{newValue}, Ints.toByteArray(originalValue), symbolName);
					}
				}

			} while (!importsFinished);
		}
	}
}
