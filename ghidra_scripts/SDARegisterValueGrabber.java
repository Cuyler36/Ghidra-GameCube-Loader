//This script searches disassembly for initialization of the GameCube & Wii SDA registers (r2 & r13), and sets the values for you.
//@author Cuyler
//@category GameCube/Wii
//@keybinding
//@menupath
//@toolbar

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.util.Msg;

public class SDARegisterValueGrabber extends GhidraScript {

	@Override
	protected void run() throws Exception {
		TrySetupSDARegisterValues();
	}
	
	private boolean TrySetDefaultRegisterValue(String registerName) {
		if (registerName == null) return false;
		
		var addressSpace = this.currentProgram.getAddressFactory().getDefaultAddressSpace();
		var codeManager = ((ProgramDB)this.currentProgram).getCodeManager();
		var iterator = codeManager.getInstructions(addressSpace.getMinAddress(), true);
		var defaultValue = 0L;
		var upperValueFound = false;
		var lowerValueFound = false;
		
		while (iterator.hasNext()) {
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
			try {
				this.currentProgram.getProgramContext().setValue(this.currentProgram.getRegister(registerName),
						addressSpace.getMinAddress(), addressSpace.getMaxAddress(), BigInteger.valueOf(defaultValue));
			} catch (ContextChangeException e) {
				e.printStackTrace();
				return false;
			}
		}
		
		return upperValueFound | lowerValueFound;
	}
	
	private void TrySetupSDARegisterValues() {
		var setR2 = this.TrySetDefaultRegisterValue("r2");
		var setR13 = this.TrySetDefaultRegisterValue("r13");
		
		if (setR2) {
			Msg.info(this, "Successfully set SDA2's (r2) value!");
		}
		else {
			Msg.warn(this, "Failed to set SDA2's (r2) value!");
		}
		
		if (setR13) {
			Msg.info(this, "Successfully set SDA's (r13) value!");
		}
		else {
			Msg.warn(this, "Failed to set SDA's (r13) value!");
		}
	}
}
