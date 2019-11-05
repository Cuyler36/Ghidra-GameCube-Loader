package gamecubeloader.analyzer;

import java.math.BigInteger;

import gamecubeloader.GameCubeLoader;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GCAnalyzer extends AbstractAnalyzer {

    public GCAnalyzer() {
        super("(GameCube/Wii) Program Analyzer", "Locates and sets SDA register values & GQR register configuration.", AnalyzerType.FUNCTION_ANALYZER);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return true;
    }
    
    public boolean canAnalyze(Program program) {
        return program.getExecutableFormat().equals(GameCubeLoader.BIN_NAME);
    }
    
    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        monitor.setMaximum(100);
        Msg.info(this, "Starting GC program analysis...");
        monitor.setMessage("Searching for SDA register (r13)...");
        var setSDA = trySetDefaultRegisterValue("r13", program, monitor);
        if (setSDA == false) {
            Msg.warn(this, "Failed to set the SDA register (r13) value!");
        }
        monitor.setProgress(10);
        monitor.setMessage("Searching for SDA2 (ToC) register (r2)...");
        var setSDA2 = trySetDefaultRegisterValue("r2", program, monitor);
        if (setSDA2 == false) {
            Msg.warn(this, "Failed to set the SDA2 (ToC) register (r2) value!");
        }
        monitor.setProgress(20);
        
        // TODO (Cuyler): Do we want a setting to toggle searching for GQR values?
        var setGQRs = false;
        for (var i = 0; i < 8; i++) {
            monitor.setMessage(String.format("Searching for GQR%d register...", i));
            var setGQR = trySetGQRegister(String.format("GQR%d", i), program, monitor);
            monitor.setProgress(30 + i * 10);
            if (setGQR == false) {
                Msg.warn(this, String.format("Failed to set the GQR%d register value!", i));
            }
            setGQRs |= setGQR;
        }
        
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
    
    protected boolean trySetDefaultRegisterValue(String registerName, Program program, TaskMonitor monitor) {
        if (registerName == null) return false;
        
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
        
        if (defaultValue != 0) {
            return setRegisterValue(registerName, defaultValue, program, codeManager, addressSpace);
        }
        
        return upperValueFound | lowerValueFound;
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
