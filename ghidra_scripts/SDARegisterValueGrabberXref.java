//This script searches disassembly for initialization of the GameCube & Wii SDA registers (r2 & r13), and sets the values for you.  It also creates xrefs and sets up data types.
//@author Cuyler, pokechu22
//@category GameCube/Wii
//@keybinding
//@menupath
//@toolbar

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

public class SDARegisterValueGrabberXref extends GhidraScript {

	@Override
	protected void run() throws Exception {
		trySetupSDARegisterValues();
	}

	private Address findDefaultRegisterValue(String registerName) {
		if (registerName == null) return null;

		var addressSpace = this.currentProgram.getAddressFactory().getDefaultAddressSpace();
		var codeManager = ((ProgramDB)this.currentProgram).getCodeManager();
		var iterator = codeManager.getInstructions(addressSpace.getMinAddress(), true);
		var defaultValue = 0L;
		var upperValueFound = false;
		var lowerValueFound = false;

		// Look for a value...
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
			} else {
				if (mnemonic.equals("addi")) {
					lowerValueFound = true;
					defaultValue += instruction.getScalar(2).getSignedValue();
				} else if (mnemonic.equals("subi")) {
					lowerValueFound = true;
					defaultValue -= instruction.getScalar(2).getSignedValue();
				} else if (mnemonic.equals("ori")) {
					lowerValueFound = true;
					defaultValue |= instruction.getScalar(2).getUnsignedValue();
				}
			}
		}

		// And now set it for the rest.
		if (upperValueFound | lowerValueFound) {
			try {
				this.currentProgram.getProgramContext().setValue(this.currentProgram.getRegister(registerName),
						addressSpace.getMinAddress(), addressSpace.getMaxAddress(), BigInteger.valueOf(defaultValue));
			} catch (ContextChangeException e) {
				printerr("Failed to set value for " + registerName + ": " + e);
				Msg.warn("Exception: ", e);
			}
			return getAddressFactory().getDefaultAddressSpace().getAddress(defaultValue);
		} else {
			return null;
		}
	}

	private boolean updateInstruction(Address r2, Address r13, Instruction instruction) {
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
				updateDataTypeFromInstruction(mnemonic, load, target);
				return true;
			}
		}
		return false;
	}

	private void updateDataTypeFromInstruction(String mnemonic, boolean load, Address address) {
		// Based on this: https://github.com/NationalSecurityAgency/ghidra/blob/49c2010b63b56c8f20845f3970fedd95d003b1e9/Ghidra/Processors/PowerPC/src/main/java/ghidra/app/plugin/core/analysis/PowerPCAddressAnalyzer.java#L600-L634
		char datatype = mnemonic.charAt(load ? 1 : 2); // The original code always uses 1 for both loads (l_z usually) and stores (st_), which doesn't work
		DataType dt = null;
		switch (datatype) {
			//case 'd': // Not a thing here
			//	dt = Undefined8DataType.dataType;
			//	break;
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
				currentProgram.getListing().createData(address, dt);
			}
			catch (CodeUnitInsertionException e) {
				// ignore
			}
			catch (DataTypeConflictException e) {
				// ignore
			}
		}
	}

	private void trySetupSDARegisterValues() {
		Address r2 = this.findDefaultRegisterValue("r2");
		Address r13 = this.findDefaultRegisterValue("r13");

		if (r2 != null) {
			println("Successfully found SDA2's (r2) value! " + r2 + " -> " + r2.subtract(0x8000));
		} else {
			printerr("Failed to find SDA2's (r2) value!");
		}

		if (r13 != null) {
			println("Successfully found SDA's (r13) value! " + r13 + " -> " + r13.subtract(0x8000));
		} else {
			printerr("Failed to find SDA's (r13) value!");
		}

		int numUpdated = 0;
		var addressSpace = this.currentProgram.getAddressFactory().getDefaultAddressSpace();
		var codeManager = ((ProgramDB)this.currentProgram).getCodeManager();
		for (Instruction instruction : codeManager.getInstructions(addressSpace.getMinAddress(), true)) {
			if (updateInstruction(r2, r13, instruction)) {
				numUpdated++;
			}
		}
		println("Updated " + numUpdated + " SDA references");
	}
}
