package gamecubeloader.dol;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class DOLHeader {
	public static final long SIZE = 0xE4;
	
	public static final String[] TEXT_NAMES = {
			".init", ".text", ".text1", ".text2", ".text3", ".text4", ".text5"
	};
	
	public static final String[] DATA_NAMES = {
		"extab", "extabindex", ".ctors", ".dtors", ".rodata", ".data", ".sdata", ".sdata2", ".bss", ".sbss", ".sbss2"	
	};
	
	public long[] textSectionOffsets;
	public long[] dataSectionOffsets;
	public long[] textSectionMemoryAddresses;
	public long[] dataSectionMemoryAddresses;
	public long[] textSectionSizes;
	public long[] dataSectionSizes;
	public long bssMemoryAddress;
	public long bssSize;
	public long entryPoint;
	
	public DOLHeader(BinaryReader reader) {
		this.readHeader(reader);
	}
	
	private void readHeader(BinaryReader reader) {
		try {
			textSectionOffsets = new long[7];
			for (int i = 0; i < 7; i++) {
				textSectionOffsets[i] = reader.readNextUnsignedInt();
			}
			
			dataSectionOffsets = new long[11];
			for (int i = 0; i < 11; i++) {
				dataSectionOffsets[i] = reader.readNextUnsignedInt();
			}
			
			textSectionMemoryAddresses = new long[7];
			for (int i = 0; i < 7; i++) {
				textSectionMemoryAddresses[i] = reader.readNextUnsignedInt();
			}
			
			dataSectionMemoryAddresses = new long[11];
			for (int i = 0; i < 11; i++) {
				dataSectionMemoryAddresses[i] = reader.readNextUnsignedInt();
			}
			
			textSectionSizes = new long[7];
			for (int i = 0; i < 7; i++) {
				textSectionSizes[i] = reader.readNextUnsignedInt();
			}
			
			dataSectionSizes = new long[11];
			for (int i = 0; i < 11; i++) {
				dataSectionSizes[i] = reader.readNextUnsignedInt();
			}
			
			bssMemoryAddress = reader.readNextUnsignedInt();
			bssSize = reader.readNextUnsignedInt();
			entryPoint = reader.readNextUnsignedInt();
		}
		catch (IOException e) {
			Msg.error(this,  "DOL Header failed to read!");
		}
	}
	
	private long alignAddress(long address) {
		if ((address & 0x1F) == 0) {
			return address;
		}
		
		return address + (0x20 - (address & 0x1F));
	}
	
	private boolean CheckAddressIntersectsOtherAddresses() {
		for (int i = 0; i < textSectionMemoryAddresses.length; i++) {
			long address = textSectionMemoryAddresses[i];
			long size = textSectionSizes[i];
			long endAddress = address + size;
			
			if (size == 0) continue;
			
			// Align end address since all sections in the DOL file must be aligned to 32 bytes.
			endAddress = alignAddress(endAddress);
			
			// Check against text section violations first.
			for (int x = 0; x < textSectionMemoryAddresses.length; x++) {
				if (x == i || textSectionSizes[x] == 0) continue;
				
				long otherAddress = textSectionMemoryAddresses[x];
				long otherSize = textSectionSizes[x];
				long otherEndAddress = otherAddress + otherSize;
				
				otherEndAddress = alignAddress(otherEndAddress);
				
				if ((address >= otherAddress && address < otherEndAddress) || (endAddress > otherAddress && endAddress < otherEndAddress)) {
					return true;
				}
			}
			
			
			// Now check against data section & text section violations.
			for (int x = 0; x < dataSectionMemoryAddresses.length; x++) {
				if (dataSectionSizes[x] == 0) continue;
				
				long otherAddress = dataSectionMemoryAddresses[x];
				long otherSize = dataSectionSizes[x];
				long otherEndAddress = otherAddress + otherSize;
				
				otherEndAddress = alignAddress(otherEndAddress);
				
				var a = address >= otherAddress && address < otherEndAddress;
				var b = endAddress > otherAddress && endAddress < otherEndAddress;
				if ((a) || (b)) {
					return true;
				}
			}
		}
		
		// Now check for data section violations.
		for (int i = 0; i < dataSectionMemoryAddresses.length; i++) {
			long address = dataSectionMemoryAddresses[i];
			long size = dataSectionSizes[i];
			long endAddress = address + size;
			
			// Align end address since all sections in the DOL file must be aligned to 32 bytes.
			endAddress = alignAddress(endAddress);
			
			if (dataSectionSizes[i] == 0) continue;
			
			// Check against text section violations first.
			for (int x = 0; x < dataSectionMemoryAddresses.length; x++) {
				if (x == i || dataSectionSizes[x] == 0) continue;
				
				long otherAddress = dataSectionMemoryAddresses[x];
				long otherSize = dataSectionSizes[x];
				long otherEndAddress = otherAddress + otherSize;
				
				otherEndAddress = alignAddress(otherEndAddress);
				
				if ((address >= otherAddress && address < otherEndAddress) || (endAddress > otherAddress && endAddress < otherEndAddress)) {
					return true;
				}
			}
		}
		
		return false;
	}
	
	public boolean CheckHeaderIsValid() {
		// Check that no section intersect any other sections.
		if (this.CheckAddressIntersectsOtherAddresses()) {
			return false;
		}
		
		// TODO: Check each section is within valid memory bounds. (0x80000000 - 0x817FFFFF)
		// TODO: Check to make sure that the file entries don't overlap each other.
		
		return true;
	}
	
	public long GetTextSectionEndAddress() {
		long lastTextSectionStartAddress = 0;
		long size = 0;
		
		for (int i = 0; i < 7; i++ ) {
			if (textSectionMemoryAddresses[i] != 0 && textSectionMemoryAddresses[i] > lastTextSectionStartAddress && textSectionSizes[i] != 0) {
				lastTextSectionStartAddress = textSectionMemoryAddresses[i];
				size = textSectionSizes[i];
			}
		}
		
		if (lastTextSectionStartAddress != 0) {
			long endAddress = lastTextSectionStartAddress + size;
			return endAddress + (0x20 - (endAddress & 0x1F));
		}
		
		return -1;
	}
}
