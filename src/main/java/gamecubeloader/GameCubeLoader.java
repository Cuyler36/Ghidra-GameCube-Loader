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

import gamecubeloader.common.Yaz0;
import gamecubeloader.dol.DOLHeader;
import gamecubeloader.dol.DOLProgramBuilder;
import gamecubeloader.rel.RELHeader;
import gamecubeloader.rel.RELProgramBuilder;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
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

	private static enum BinaryType {
		DOL, REL
	}
	
	private static final String autoloadCmd = Loader.COMMAND_LINE_ARG_PREFIX + "-autoloadMaps";
	
	private BinaryType binaryType;
	private DOLHeader dolHeader;
	private RELHeader relHeader;
	
	@Override
	public String getName() {
		return "Nintendo GameCube Binary";
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
			
			
			// Check for DOL first.
			DOLHeader tempDolHeader = new DOLHeader(reader); 
			if (tempDolHeader.CheckHeaderIsValid()) {
				binaryType = BinaryType.DOL;
				dolHeader = tempDolHeader;
			}
			else {
				// TODO: Check for REL now.
				RELHeader tempRelHeader = new RELHeader(reader);
				if (tempRelHeader.IsValid(reader)) {
					binaryType = BinaryType.REL;
					relHeader = tempRelHeader;
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
			success = this.loadInto(provider, loadSpec, options, log, program, monitor,
					MemoryConflictHandler.ALWAYS_OVERWRITE);
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
            MessageLog messageLog, Program program, TaskMonitor monitor, MemoryConflictHandler memoryConflictHandler) 
            throws IOException {
    	
    	boolean autoLoadMaps = false;
    	// TODO: There's definitely a better way to do this.
    	// Seems like OptionListerner interface is probably the best way.
    	for (var option : options) {
    		if (option.getArg() == GameCubeLoader.autoloadCmd) {
    			autoLoadMaps = (boolean) option.getValue();
    			break;
    		}
    	}
    	
        if (this.binaryType == BinaryType.DOL) {
        	new DOLProgramBuilder(dolHeader, provider, program, memoryConflictHandler, monitor, autoLoadMaps);
        }
        else if (this.binaryType == BinaryType.REL) {
        	try {
				new RELProgramBuilder(relHeader, provider, program, memoryConflictHandler, monitor, autoLoadMaps);
			} catch (AddressOverflowException | AddressOutOfBoundsException | MemoryAccessException e ) {
				e.printStackTrace();
			}
        }
        
        return true;
    }

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		
		list.add(new Option("Automatically load symbol map files with corresponding names", true, Boolean.class,
				GameCubeLoader.autoloadCmd));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}
