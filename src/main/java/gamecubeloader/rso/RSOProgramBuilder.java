package gamecubeloader.rso;

import gamecubeloader.common.CodeWarriorDemangler;
import gamecubeloader.common.SectionInfo;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.Loader;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.io.FilenameUtils;
import org.python.google.common.primitives.Ints;

import java.io.IOException;

public class RSOProgramBuilder {
	// Relocation types supported by RSOLink.
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

	public static void load(Program program, Loader.ImporterSettings settings, RSOHeader rso)
		throws LoadException {
		var baseAddress = 0x80000000L;
		var provider = settings.provider();
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		var symbolTable = program.getSymbolTable();
		var memory = program.getMemory();

		RSOModule rsoModule;
		try {
			rsoModule = new RSOModule(rso, provider);
		} catch (IOException e) {
			throw new LoadException(e);
		}
		rsoModule.header.bssSection = 0;

		var currentOutputAddress = baseAddress;
		var sectionsAddress = new Address[(int) rsoModule.header.numSections];
		var blockNamePrefix = FilenameUtils.getBaseName(program.getName());

		var predefinedSectionTypes = RSOSection.values();

		var unk = 0;
		for (var s = 0; s < rsoModule.header.numSections; s++) {
			var section = rsoModule.header.sections[s];
			sectionsAddress[s] = Address.NO_ADDRESS;
			if (section.size != 0) {
				if (section.address != 0) {

					RSOSection sectionType = null;
					var sectionName = "";
					if (s < predefinedSectionTypes.length) {
						sectionType = predefinedSectionTypes[s];
						sectionName = sectionType.getName();
					}

					if (sectionType == null || sectionName.isEmpty()) {
						sectionType = RSOSection.NULL;
						sectionName = String.format(".unknown%02d", unk++);
					}

					var blockName = String.format("%s%s", blockNamePrefix, sectionName);
					var sectionAddress = addressSpace.getAddress(currentOutputAddress);

					try {
						MemoryBlockUtils.createInitializedBlock(program, false, blockName, sectionAddress,
							provider.getInputStream(section.address), section.size, "", null,
							sectionType.isReadable(), sectionType.isWriteable(), sectionType.isExecutable(), settings.log(), settings.monitor());
					} catch (IOException | AddressOverflowException e) {
						throw new LoadException(String.format("Failed to load RSO section %d", s), e);
					}

					sectionsAddress[s] = sectionAddress;
					currentOutputAddress += section.size;

				} else if (rsoModule.header.bssSection == 0) {
					rsoModule.header.bssSection = s;
				}
			}
		}

		// Add bss section.
		if (rsoModule.header.bssSize != 0 && rsoModule.header.bssSection != 0) {
			currentOutputAddress = align(currentOutputAddress, 0x4);

			var bssSectionAddress = addressSpace.getAddress(currentOutputAddress);
			MemoryBlockUtils.createUninitializedBlock(program, false,
				blockNamePrefix + ".bss", bssSectionAddress, rsoModule.header.bssSize, "", null,
				true, true, false, null);

			// Set the bss virtual memory address.
			sectionsAddress[rsoModule.header.bssSection] = bssSectionAddress;

			currentOutputAddress += rsoModule.header.bssSize;
		}

		// Mark the Relocatable Module's prolog, epilog, & unresolved functions as external entry points.
		if (rsoModule.header.prologSection != 0) {
			var prologAddress = sectionsAddress[rsoModule.header.prologSection].add(rsoModule.header.prologOffset);
			symbolTable.addExternalEntryPoint(prologAddress);
		}

		if (rsoModule.header.unresolvedSection != 0) {
			var unresolvedAddress = sectionsAddress[rsoModule.header.unresolvedSection].add(rsoModule.header.unresolvedOffset);
			symbolTable.addExternalEntryPoint(unresolvedAddress);
		}

		if (rsoModule.header.epilogSection != 0) {
			var epilogAddress = sectionsAddress[rsoModule.header.epilogSection].add(rsoModule.header.epilogOffset);
			symbolTable.addExternalEntryPoint(epilogAddress);
		}

		// Align the output address for the external block
		currentOutputAddress = align(currentOutputAddress, 4);

		var demanglerOptions = new DemanglerOptions();
		demanglerOptions.setApplySignature(true);

		// Apply external relocation
		var importedSymbols = rsoModule.getImportSymbols();
		Msg.info(RSOProgramBuilder.class, String.format("Imported Symbol %d", importedSymbols.size()));

		if (!importedSymbols.isEmpty()) {
			// Create EXTERNAL section
			final int IMP_SYMBOL_SIZE = 4;
			var externalBlockSize = importedSymbols.size() * IMP_SYMBOL_SIZE;
			var externalBlockOffset = currentOutputAddress;
			var externalBlock = createExternalBlock(settings, program.getMemory(),
				addressSpace.getAddress(currentOutputAddress), externalBlockSize);

			if (externalBlock == null) {
				return;
			}

			for (var impIndex = 0; impIndex < importedSymbols.size(); ++impIndex) {
				var importedSymbol = importedSymbols.get(impIndex);

				var importedAddress = externalBlockOffset;
				externalBlockOffset += IMP_SYMBOL_SIZE;

				var appliedSymbol = false;

				var relocationIndex = importedSymbol.relOffset / RSOModule.Relocation.SIZE;
				var externalRelocations = rsoModule.getExternalRelocations();
				while (relocationIndex < externalRelocations.size()) {
					var externalRelocation = externalRelocations.get((int) relocationIndex);
					relocationIndex += 1;

					if (impIndex != externalRelocation.getSymbolIndex()) {
						break;
					}

					try {
						if (!appliedSymbol) {
							var relocationType = externalRelocation.getRelocationType();
							var originalValue = memory.getInt(addressSpace.getAddress(baseAddress + externalRelocation.offset));

							// TODO(InusualZ): Is there a better way to detect if it's a function?
							var opcode = originalValue & 0xFC000000;
							var isBranchOpCode = opcode == 16 || opcode == 18 || opcode == 19;
							var createThunkFunction = isBranchOpCode && relocationType != R_PPC_ADDR32 && relocationType != R_PPC_ADDR16_LO;

							applySymbol(program, importedSymbol.name, addressSpace.getAddress(importedAddress),
								demanglerOptions, IMP_SYMBOL_SIZE, createThunkFunction, settings.monitor());

							appliedSymbol = true;
						}

						applyRelocation(program, rso, externalRelocation, importedAddress, importedSymbol.name, sectionsAddress);
					} catch (MemoryAccessException e) {
						throw new LoadException(String.format("Failed to apply external relocation %d", relocationIndex), e);
					}
				}

				if (appliedSymbol) {
					Msg.info(RSOProgramBuilder.class, String.format("Applied relocation for `%s`", importedSymbol.name));
				} else {
					Msg.error(RSOProgramBuilder.class, String.format("Unable to relocate `%s`", importedSymbol.name));
				}
			}
		}

		// Apply Internal Relocations
		for (var relocation : rsoModule.getInternalRelocations()) {
			var section = rsoModule.header.sections[relocation.getSectionIndex()];

			try {
				applyRelocation(program, rso, relocation, section.address, "__INTERNAL__", sectionsAddress);
			} catch (MemoryAccessException e) {
				Msg.error(RSOProgramBuilder.class, String.format("Out of bound relocation - { .off=%08X, .ind=%d, rlt=%d, soff=%08X }",
					relocation.offset, relocation.getSectionIndex(), relocation.getRelocationType(), relocation.addend), e);
			}
		}

		// Apply Symbols For Exported Functions
		rsoModule.getExportSymbols().forEach(exportSymbol -> {
			var sectionAddress = sectionsAddress[(int) exportSymbol.section];
			var symbolAddress = sectionAddress.add(exportSymbol.value);
			applySymbol(program, exportSymbol.name, symbolAddress, demanglerOptions, 0, false, settings.monitor());
		});
	}

	private static void applyRelocation(Program program, RSOHeader rso, RSOModule.Relocation relocation, long addr, String symbolName, Address[] sectionsAddress)
		throws MemoryAccessException {
		var targetAddress = translatePhysicalAddress(rso, relocation.offset, sectionsAddress);
		var addressValue = addr + relocation.addend;

		var memory = program.getMemory();
		var originalValue = memory.getInt(targetAddress);
		var writeValue = 0L;

		var relocationType = relocation.getRelocationType();
		switch (relocationType) {
			case R_PPC_ADDR16_HA:
				writeValue = (addressValue >> 16) & 0xFFFF;
				if ((addressValue & 0x8000) != 0) {
					writeValue += 1;
				}

				memory.setShort(targetAddress, (short) writeValue, true);
				break;

			case R_PPC_ADDR24:
				writeValue = (addressValue & 0x3FFFFFC) |
					(originalValue & 0xFC000003);

				memory.setInt(targetAddress, (int) writeValue, true);
				break;

			case R_PPC_ADDR32:
				memory.setInt(targetAddress, (int) addressValue, true);
				break;

			case R_PPC_ADDR16:
			case R_PPC_ADDR16_LO:
				writeValue = (addressValue) & 0xFFFF;

				memory.setShort(targetAddress, (short) writeValue, true);
				break;

			case R_PPC_ADDR16_HI:
				writeValue = ((addressValue) >> 16) & 0xFFFF;

				memory.setShort(targetAddress, (short) writeValue, true);
				break;

			case R_PPC_NONE:
				break;

			case R_PPC_REL24:
				writeValue = ((addressValue - targetAddress.getOffset()) & 0x3FFFFFC) |
					(originalValue & 0xFC000003);

				memory.setInt(targetAddress, (int) writeValue, true);
				break;

			case R_PPC_ADDR14:
			case R_PPC_ADDR14_BRNTAKEN:
			case R_PPC_ADDR14_BRTAKEN:
				writeValue = (addressValue & 0xFFFC) |
					(originalValue & 0xFFFF0003);

				memory.setInt(targetAddress, (int) writeValue, true);
				break;

			case R_PPC_REL14:
				writeValue = ((addressValue - targetAddress.getOffset()) & 0xFFFC) |
					(originalValue & 0xFFFF0003);

				memory.setInt(targetAddress, (int) writeValue, true);
				break;

			default:
				Msg.warn(RSOProgramBuilder.class, String.format("Relocations: Unsupported relocation type %X", relocationType));
				break;
		}

		long newValue = memory.getInt(targetAddress) & 0xFFFFFFFFL;
		program.getRelocationTable().add(targetAddress, Status.APPLIED, relocationType, new long[]{newValue},
			Ints.toByteArray(originalValue), symbolName);
	}

	private static Address translatePhysicalAddress(RSOHeader rso, long physicalAddress, Address[] sectionsAddress) {
		SectionInfo sectionInRange = null;
		int sectionIndex = -1;
		for (var s = 0; s < rso.sections.length; ++s) {
			var section = rso.sections[s];
			if (section.size == 0 || section.address == 0) {
				continue;
			}

			var start = section.address;
			var end = start + section.size;

			if (physicalAddress >= start && physicalAddress < end) {
				sectionInRange = section;
				sectionIndex = s;
				break;
			}
		}

		if (sectionInRange == null) {
			throw new AddressOutOfBoundsException(String.format("Physical address `%08X` is not in range of a section",
				physicalAddress));
		}

		// Calculate offset, relative to the section address
		var offset = physicalAddress - sectionInRange.address;

		// We get the virtual section address of the same section
		var virtualSectionAddress = sectionsAddress[sectionIndex];

		return virtualSectionAddress.add(offset);
	}

	private static void applySymbol(Program program, String mangled, Address symbolAddress, DemanglerOptions demanglerOptions, int symbolSize,
									boolean createThunkFunction, TaskMonitor monitor) {
		// Demangle the name using CodeWarriors scheme.
		DemangledObject demangledNameObject = null;
		try {
			demangledNameObject = CodeWarriorDemangler.demangleSymbol(mangled);
		} catch (Exception e) {
			// TODO(jstpierre): Investigate the failed demanglings. Sometimes these are literal symbols.
		}

		var symbolTable = program.getSymbolTable();
		var globalNamespace = program.getGlobalNamespace();
		var demangledName = demangledNameObject == null ? mangled : demangledNameObject.getName();

		try {
			symbolTable.createLabel(symbolAddress, demangledName, globalNamespace, SourceType.ANALYSIS);

			// If it's a function, create it.
			var block = program.getMemory().getBlock(symbolAddress);

			// TODO(InsualZ): Is this correct?
			var isFunction = demangledNameObject instanceof DemangledFunction;

			if ((isFunction || createThunkFunction) && symbolSize > 3 && block != null && block.isExecute() &&
				!block.getName().equals("RAM")) {
				var addressSet = new AddressSet(symbolAddress, symbolAddress.add(symbolSize - 1));
				try {
					var functionManager = program.getFunctionManager();
					var function = functionManager.createFunction(demangledName, globalNamespace,
						symbolAddress, addressSet, SourceType.ANALYSIS);

					if (createThunkFunction) {
						functionManager.createThunkFunction(demangledName, globalNamespace, symbolAddress, addressSet,
							function, SourceType.ANALYSIS);
					}
				} catch (OverlappingFunctionException ignored) {
				}
			}

			// Try applying the function arguments & return type using the demangled info.
			if (demangledNameObject != null) {
				try {
					demangledNameObject.applyTo(program, symbolAddress, demanglerOptions, monitor);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		} catch (InvalidInputException e) {
			Msg.error(RSOProgramBuilder.class, "RSO Program Builder: An error occurred when attempting to load symbol: " +
				mangled);
		}
	}

	private static long align(long address, int alignment) {
		var inverse = alignment - 1;
		if ((address & inverse) != 0) {
			address = (address + inverse) & ~inverse;
		}

		return address;
	}

	private static MemoryBlock createExternalBlock(Loader.ImporterSettings settings, Memory memory, Address sectionOffset, long size) {
		try {
			var block = memory.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME,
				sectionOffset, size, false);

			// assume any value in external is writable.
			block.setWrite(true);
			block.setSourceName(settings.provider().getName());
			block.setComment(
				"NOTE: This block is artificial and is used to make relocations work correctly");

			return block;
		} catch (Exception e) {
			settings.log().appendMsg("Error creating external memory block: " + " - " + getMessage(e));
		}

		return null;
	}

	private static String getMessage(Exception e) {
		String msg = e.getMessage();
		if (msg == null) {
			msg = e.toString();
		}
		return msg;
	}
}
