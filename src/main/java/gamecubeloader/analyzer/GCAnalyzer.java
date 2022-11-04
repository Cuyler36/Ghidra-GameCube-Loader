package gamecubeloader.analyzer;

import java.math.BigInteger;

import gamecubeloader.GameCubeLoader;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GCAnalyzer extends AbstractAnalyzer {
    private static final String SEARCH_SDA_REGISTERS_OPTION = "Search for SDA & SDA2 (ToC) Registers Initialization";
    private static final String SEARCH_GQR_REGISTERS_OPTION = "Search for GQR Registers Initialization";
    
    private boolean searchSDARegs = true;
    private boolean searchGQRRegs = true;
    
    public GCAnalyzer() {
        super("(GameCube/Wii) Program Analyzer", "Locates and sets SDA register values & GQR register configuration.", AnalyzerType.FUNCTION_ANALYZER);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        if (program.getLanguageID().getIdAsString().equals("PowerPC:BE:32:Gekko_Broadway") &&
                program.getExecutableFormat().equals(GameCubeLoader.BIN_NAME)) {
            return true;
        }

        return false;
    }
    
    @Override
    public boolean canAnalyze(Program program) {
        if (program.getLanguageID().getIdAsString().equals("PowerPC:BE:32:Gekko_Broadway")) {
            return true;
        }
        return program.getExecutableFormat().equals(GameCubeLoader.BIN_NAME);
    }
    
    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(GCAnalyzer.SEARCH_SDA_REGISTERS_OPTION, OptionType.BOOLEAN_TYPE, true, null, "");
        options.registerOption(GCAnalyzer.SEARCH_GQR_REGISTERS_OPTION, OptionType.BOOLEAN_TYPE, true, null, "");
    }
    
    @Override
    public void optionsChanged(Options options, Program program) {
        this.searchSDARegs = options.getBoolean(GCAnalyzer.SEARCH_SDA_REGISTERS_OPTION, true);
        this.searchGQRRegs = options.getBoolean(GCAnalyzer.SEARCH_GQR_REGISTERS_OPTION, true);
    }
    
    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        monitor.setMaximum(100);
        Msg.info(this, "Starting GC program analysis...");
        var setSDA = false;
        var setSDA2 = false;
        
        if (this.searchSDARegs == true) {
            monitor.setMessage("Searching for SDA register (r13)...");
            var r13 = trySetDefaultRegisterValue("r13", program, monitor);
            setSDA = r13 != null;
            if (setSDA == false) {
                Msg.warn(this, "Failed to set the SDA register (r13) value!");
            }
            monitor.setProgress(10);
        
            monitor.setMessage("Searching for SDA2 (ToC) register (r2)...");
            var r2 = trySetDefaultRegisterValue("r2", program, monitor);
            setSDA2 = r2 != null;
            if (setSDA2 == false) {
                Msg.warn(this, "Failed to set the SDA2 (ToC) register (r2) value!");
            }
            
            int numUpdated = 0;
            var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
            var codeManager = ((ProgramDB)program).getCodeManager();
            for (Instruction instruction : codeManager.getInstructions(addressSpace.getMinAddress(), true)) {
                if (updateInstruction(program, r2, r13, instruction)) {
                    numUpdated++;
                }
            }
            Msg.debug(this, "Updated " + numUpdated + " SDA references");
        }
        monitor.setProgress(20);
        
        
        var setGQRs = false;
        if (this.searchGQRRegs == true) {
            for (var i = 0; i < 8; i++) {
                monitor.setMessage(String.format("Searching for GQR%d register...", i));
                var setGQR = trySetGQRegister(String.format("GQR%d", i), program, monitor);
                monitor.setProgress(30 + i * 10);
                if (setGQR == false) {
                    Msg.warn(this, String.format("Failed to set the GQR%d register value!", i));
                }
                setGQRs |= setGQR;
            }
        }
        monitor.setProgress(100);
        
        return setSDA | setSDA2 | setGQRs;
    }

    protected boolean setRegisterValue(String registerName, long defaultValue, Program program, CodeManager cm, AddressSpace addrSpace) {
        Register reg = program.getRegister(registerName);
        Address startAddr = cm.getInstructionAfter(addrSpace.getMinAddress()).getAddress();
        Address endAddr = cm.getInstructionBefore(addrSpace.getMaxAddress()).getAddress();
        Msg.debug(this, String.format("Writing regs to minAddr=0x%08X through maxAddr=0x%08X", startAddr.getUnsignedOffset(), endAddr.getUnsignedOffset()));
        BigInteger val = BigInteger.valueOf(defaultValue);
        var cmd1 = new SetRegisterCmd(reg, startAddr, endAddr, null);
        var cmd2 = new SetRegisterCmd(reg, startAddr, endAddr, val);
        var cmd = new CompoundCmd("Update Register Range");
        cmd.add(cmd1);
        cmd.add(cmd2);
        var result =  cmd.applyTo(program);
        Msg.debug(this, String.format("Reg value: %08X", program.getProgramContext().getRegisterValue(reg, startAddr).getUnsignedValue().longValue()));
        return result;
    }
    
    protected Address trySetDefaultRegisterValue(String registerName, Program program, TaskMonitor monitor) {
        if (registerName == null) return null;
        
        var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        var codeManager = ((ProgramDB)program).getCodeManager();
        var iterator = codeManager.getInstructions(addressSpace.getMinAddress(), true);
        var defaultValue = 0L;
        var upperValueFound = false;
        var lowerValueFound = false;
        
        while (monitor.isCancelled() == false && iterator.hasNext()) {
            if (lowerValueFound && upperValueFound) break;
            
            var instruction = iterator.next();
            var mnemonic = instruction.getMnemonicString();
            
            if (mnemonic.equals("blr") && (upperValueFound || lowerValueFound)) break;
            
            Register register = instruction.getRegister(0);
            
            if (register == null) continue;
            if (register.getName().equals(registerName) == false) continue;
            
            if (mnemonic.equals("lis")) {
                if (upperValueFound == true) continue;
                
                upperValueFound = true;
                defaultValue = (instruction.getScalar(1).getUnsignedValue() & 0xFFFF) << 16;
            }
            else {
                if (mnemonic.equals("addi")) {
                    lowerValueFound = true;
                    defaultValue += instruction.getScalar(2).getSignedValue();
                }
                else if (mnemonic.equals("subi")) {
                    lowerValueFound = true;
                    defaultValue -= instruction.getScalar(2).getSignedValue();
                }
                else if (mnemonic.equals("ori")) {
                    lowerValueFound = true;
                    defaultValue |= instruction.getScalar(2).getUnsignedValue();
                }
            }
        }
        
        if (defaultValue != 0 && setRegisterValue(registerName, defaultValue, program, codeManager, addressSpace)) {
            return addressSpace.getAddress(defaultValue);
        }
        
        return null;
    }
    
    private boolean updateInstruction(Program program, Address r2, Address r13, Instruction instruction) {
        String mnemonic = instruction.getMnemonicString();
        if (mnemonic.equals("subi")) {
            Object[] op2 = instruction.getOpObjects(1);
            Object[] op3 = instruction.getOpObjects(2);
            if (op2.length == 1 && op2[0] instanceof Register && op3.length == 1 && op3[0] instanceof Scalar) {
                Register reg = (Register)op2[0];
                Scalar scalar = (Scalar)op3[0];
                Address target;
                if (reg.getName().equals("r13")) {
                    if (r13 == null) return false;
                    target = r13.subtract(scalar.getValue());
                } else if (reg.getName().equals("r2")) {
                    if (r2 == null) return false;
                    target = r2.subtract(scalar.getValue());
                } else {
                    return false;
                }
                instruction.addOperandReference(0/* dest */, target, RefType.DATA, SourceType.ANALYSIS);
                return true;
            }
        } else if (mnemonic.startsWith("l") || mnemonic.startsWith("s")) {
            boolean load = (mnemonic.startsWith("l"));
            Object[] op2 = instruction.getOpObjects(1);
            if (op2.length == 2 && op2[0] instanceof Scalar && op2[1] instanceof Register) {
                // Make a jank assumption that this implies load/store
                Register reg = (Register)op2[1];
                Scalar scalar = (Scalar)op2[0];
                Address target;
                if (reg.getName().equals("r13")) {
                    if (r13 == null) return false;
                    target = r13.add(scalar.getValue());
                } else if (reg.getName().equals("r2")) {
                    if (r2 == null) return false;
                    target = r2.add(scalar.getValue());
                } else {
                    return false;
                }
                instruction.addOperandReference(1/* dest */, target, load ? RefType.READ : RefType.WRITE, SourceType.ANALYSIS);
                updateDataTypeFromInstruction(program, mnemonic, load, target);
                return true;
            }
        }
        return false;
    }

    protected void updateDataTypeFromInstruction(Program program, String mnemonic, boolean load, Address address) {
        // Based on this: https://github.com/NationalSecurityAgency/ghidra/blob/49c2010b63b56c8f20845f3970fedd95d003b1e9/Ghidra/Processors/PowerPC/src/main/java/ghidra/app/plugin/core/analysis/PowerPCAddressAnalyzer.java#L600-L634
        char datatype = mnemonic.charAt(load ? 1 : 2); // The original code always uses 1 for both loads (l_z usually) and stores (st_), which doesn't work
        DataType dt = null;
        switch (datatype) {
            //case 'd': // Not a thing here
            //  dt = Undefined8DataType.dataType;
            //  break;
            case 'w':
                dt = Undefined4DataType.dataType;
                break;
            case 'h':
                dt = Undefined2DataType.dataType;
                break;
            case 'b':
                dt = Undefined1DataType.dataType;
                break;
            // Missing in the original
            case 'f':
                // lfs[u][x], stfs[u][x] for single
                // lfd[u][x], stfd[u][x] for double
                switch (mnemonic.charAt(load ? 2 : 3)) {
                case 's':
                    dt = FloatDataType.dataType;
                    break;
                case 'd':
                    dt = DoubleDataType.dataType;
                    break;
                }
                break;
        }
        if (dt != null) {
            try {
                program.getListing().createData(address, dt);
            }
            catch (CodeUnitInsertionException e) {
                // ignore
            }
        }
    }
    
    protected boolean trySetGQRegister(String gqrName, Program program, TaskMonitor monitor) {
        if (gqrName == null) return false;
        
        var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        var codeManager = ((ProgramDB)program).getCodeManager();
        var iterator = codeManager.getInstructions(addressSpace.getMinAddress(), true);
        var defaultValue = 0L;
        var upperValueFound = false;
        var lowerValueFound = false;
        
        while (monitor.isCancelled() == false && iterator.hasNext()) {
            if (lowerValueFound && upperValueFound) break;
            
            var instruction = iterator.next();
            var mnemonic = instruction.getMnemonicString();
            
            if (mnemonic.equals("blr") && (upperValueFound || lowerValueFound)) break;
            
            Register register = instruction.getRegister(0);
            
            if (register == null) continue;
            if (register.getName().equals(gqrName) == false) continue;
            
            if (mnemonic.equals("mtspr")) {
                // Back up until we've found where the other register is set.
                Register gqrHolder = instruction.getRegister(1);
                var minAddr = codeManager.getInstructionAfter(addressSpace.getMinAddress()).getAddress().getUnsignedOffset();
                var invalid = false;
                while (monitor.isCancelled() == false && instruction != null &&
                       instruction.getAddress().getUnsignedOffset() > minAddr && invalid == false) {
                    if (lowerValueFound && upperValueFound)
                        break;
                    instruction = instruction.getPrevious();
                    if (instruction == null)
                        break;
                    if (instruction.getMnemonicString().contains("bl"))
                        break;
                    
                    Register rt = instruction.getRegister(0);
                    if (rt != null && rt.equals(gqrHolder)) {
                        switch (instruction.getMnemonicString()) {
                        // Lower
                        case "li":
                            defaultValue |= instruction.getScalar(1).getSignedValue();
                            lowerValueFound = true;
                            break;
                        case "ori":
                            defaultValue |= instruction.getScalar(2).getUnsignedValue();
                            lowerValueFound = true;
                            break;
                        case "addi":
                            defaultValue += instruction.getScalar(2).getSignedValue();
                            lowerValueFound = true;
                            break;
                        case "subi":
                            defaultValue -= instruction.getScalar(2).getSignedValue();
                            lowerValueFound = true;
                            break;
                        // Upper
                        case "lis":
                            defaultValue |= (instruction.getScalar(1).getUnsignedValue() & 0xFFFF) << 16;
                            upperValueFound = true;
                            break;
                        case "oris":
                            defaultValue |= (instruction.getScalar(2).getUnsignedValue() & 0xFFFF) << 16;
                            upperValueFound = true;
                            break;
                         // Fail all other cases when we haven't found the value.
                        default:
                            upperValueFound = lowerValueFound = false;
                            invalid = true;
                            break;
                        }
                    }
                }
            }
        }
        
        if (upperValueFound | lowerValueFound) {
            return setRegisterValue(gqrName, defaultValue, program, codeManager, addressSpace);
        }
        
        return upperValueFound | lowerValueFound;
    }
}
