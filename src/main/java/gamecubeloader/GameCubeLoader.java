/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gamecubeloader;

import java.io.IOException;
import java.util.*;

import gamecubeloader.apploader.ApploaderHeader;
import gamecubeloader.apploader.ApploaderProgramBuilder;
import gamecubeloader.common.Yaz0;
import gamecubeloader.dol.DOLHeader;
import gamecubeloader.dol.DOLProgramBuilder;
import gamecubeloader.ramdump.RAMDumpProgramBuilder;
import gamecubeloader.rel.RELHeader;
import gamecubeloader.rel.RELProgramBuilder;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GameCubeLoader extends BinaryLoader {
    public static final String BIN_NAME = "Nintendo GameCube Binary";
    
	private static enum BinaryType {
		DOL, REL, APPLOADER, RAMDUMP, UNKNOWN
	}
	
	private static final int RAM_MEM1_SIZE = 0x01800000;
	
	private static final String ADD_RESERVED_AND_HARDWAREREGISTERS = "Create OS global memory section & hardware register memory sections";
	private static final String AUTOLOAD_MAPS_OPTION_NAME = "Automatically load symbol map files with corresponding names";
	private static final String ADD_RELOCATIONS_OPTION_NAME = "Add relocation info to Relocation Table view (WARNING: Slow when using symbol maps)";
	private static final String SPECIFY_BINARY_MEM_ADDRESSES = "Manually specify the memory address of each module loaded";
	
	private BinaryType binaryType = BinaryType.UNKNOWN;
	private DOLHeader dolHeader;
	private RELHeader relHeader;
	private ApploaderHeader apploaderHeader;
	
	@Override
	public String getName() {
		return BIN_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		Yaz0 yaz0 = new Yaz0();
		if (yaz0.IsValid(provider)) {
			provider = yaz0.Decompress(provider);
			var reader = new BinaryReader(provider, false);
			var header = new RELHeader(reader);
			
			if (header.IsValid(reader)) {
				binaryType = BinaryType.REL;
				relHeader = header;
			}
		}
		else {
			// Attempt to determine the binary type based off of the info in it.
			BinaryReader reader = new BinaryReader(provider, false);
			
			/* Check for RAM dump. */
            if (provider.length() == GameCubeLoader.RAM_MEM1_SIZE) {
                /* Determine if GC or Wii */
                long magic0 = reader.readUnsignedInt(0x18); /* 0x5D1C9EA3 for Wii. */
                long magic1 = reader.readUnsignedInt(0x1C); /* 0xC2339F3D for GC. */
                /* TODO: Are there better checks for this? */
                if (magic0 == 0x5D1C9EA3L || magic1 == 0xC2339F3DL) {
                    binaryType = BinaryType.RAMDUMP;
                }
            }
            else {
    			/* Check for DOL executable. */
    			DOLHeader tempDolHeader = new DOLHeader(reader); 
    			if (tempDolHeader.CheckHeaderIsValid()) {
    				binaryType = BinaryType.DOL;
    				dolHeader = tempDolHeader;
    			}
    			else {
    				/* Check for REL module. */
    				RELHeader tempRelHeader = new RELHeader(reader);
    				if (tempRelHeader.IsValid(reader)) {
    					binaryType = BinaryType.REL;
    					relHeader = tempRelHeader;
    				}
    				else {
    					/* Check if it's an apploader. */
    					ApploaderHeader tempAppHeader = new ApploaderHeader(reader);
    					if (tempAppHeader.IsValid()) {
    						binaryType = BinaryType.APPLOADER;
    						apploaderHeader = tempAppHeader;
    					}
    				}
    			}
            }
		}
		
		if (binaryType != null) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("PowerPC:BE:32:Gekko_Broadway", "default"), true));
		}
		
		return loadSpecs;
	}

	@Override
	protected List<Program> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);
		
		Address baseAddress = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		Program program = createProgram(provider, programName, baseAddress, getName(),
				importerLanguage, importerCompilerSpec, consumer);
		
		boolean success = false;
		try {
			success = this.loadInto(provider, loadSpec, options, log, program, monitor);
		}
		finally {
			if (!success) {
				program.release(consumer);
				program = null;
			}
		}
		
		List<Program> results = new ArrayList<Program>();
		if (program != null) {
			results.add(program);
		}
		
		return results;
	}
	
    @Override
    protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            MessageLog messageLog, Program program, TaskMonitor monitor) 
            throws IOException {
    	
    	if (this.binaryType != BinaryType.UNKNOWN) {
	    	boolean autoLoadMaps = OptionUtils.getBooleanOptionValue(AUTOLOAD_MAPS_OPTION_NAME, options, true);
	    	boolean saveRelocations = OptionUtils.getBooleanOptionValue(ADD_RELOCATIONS_OPTION_NAME, options, false);
	    	boolean createDefaultSections = OptionUtils.getBooleanOptionValue(ADD_RESERVED_AND_HARDWAREREGISTERS, options, true);
	    	boolean specifyFileMemAddresses = OptionUtils.getBooleanOptionValue(SPECIFY_BINARY_MEM_ADDRESSES, options, false);
	    	
	    	if (this.binaryType == BinaryType.RAMDUMP) {
	    	    new RAMDumpProgramBuilder(provider, program, monitor, createDefaultSections, messageLog);
	    	}
	    	else if (this.binaryType == BinaryType.DOL) {
	        	new DOLProgramBuilder(dolHeader, provider, program, monitor, autoLoadMaps, createDefaultSections, messageLog);
	        }
	        else if (this.binaryType == BinaryType.REL) {
	        	try {
	        		// We have to check if the source file is compressed & decompress it again if it is.
	        		var file = provider.getFile();
	        		Yaz0 yaz0 = new Yaz0();
	        		if (yaz0.IsValid(provider)) {
	        			provider = yaz0.Decompress(provider);
	        		}
	        		
					new RELProgramBuilder(relHeader, provider, program, monitor, file,
							autoLoadMaps, saveRelocations, createDefaultSections, specifyFileMemAddresses, messageLog);
				} catch (AddressOverflowException | AddressOutOfBoundsException | MemoryAccessException e ) {
					e.printStackTrace();
				}
	        }
	        else {
	        	new ApploaderProgramBuilder(apploaderHeader, provider, program, monitor, createDefaultSections, messageLog);
	        }
        	return true;
    	}
    	return false;
    }

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		
		list.add(new Option(AUTOLOAD_MAPS_OPTION_NAME, true, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-autoloadMaps"));
		list.add(new Option(ADD_RELOCATIONS_OPTION_NAME, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-saveRelocations"));
		list.add(new Option(ADD_RESERVED_AND_HARDWAREREGISTERS, true, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-addSystemMemorySections"));
		list.add(new Option(SPECIFY_BINARY_MEM_ADDRESSES, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-specifyFileMemAddrs"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
