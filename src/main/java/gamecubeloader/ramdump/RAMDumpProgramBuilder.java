package gamecubeloader.ramdump;

import java.io.FileNotFoundException;
import java.io.FileReader;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import gamecubeloader.common.SymbolLoader;
import gamecubeloader.common.SystemMemorySections;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
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
        }
        catch (Exception e) {
            e.printStackTrace();
            return;
        }
        
        /* Optionally load symbol map */
        if (OptionDialog.showOptionNoCancelDialog(null, "Load Symbols?", "Would you like to load a symbol map for this RAM dump?", "Yes", "No", null) == 1) {
            var fileChooser = new GhidraFileChooser(null);
            fileChooser.setCurrentDirectory(provider.getFile().getParentFile());
            fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
            var selectedFile = fileChooser.getSelectedFile(true);
            
            if (selectedFile != null) {
                FileReader reader = null;
                try {
                    reader = new FileReader(selectedFile);
                }
                catch (FileNotFoundException e) {
                    Msg.error(this, String.format("Failed to open the symbol map file!\nReason: %s", e.getMessage()));
                }
                
                if (reader != null) {
                    SymbolLoader loader = new SymbolLoader(this.program, monitor, reader, this.baseAddress, 0, -1, "RAM Dump", false);
                    loader.ApplySymbols();
                }
            }
        }
    }
}
