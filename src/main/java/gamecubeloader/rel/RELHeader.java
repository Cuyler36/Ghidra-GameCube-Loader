package gamecubeloader.rel;

import java.io.IOException;

import gamecubeloader.common.SectionInfo;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class RELHeader {
	public long moduleId;
	public long previousModuleAddress;
	public long nextModuleAddress;
	public long sectionCount;
	
	public long sectionTableOffset;
	public long moduleNameOffset;
	public long moduleNameLength;
	public long moduleVersion; // REL Version
	
	public long bssSize;
	public long relocationTableOffset;
	public long importTableOffset;
	public long importTableSize;
	
	public int prologSectionId;
	public int epilogSectionId;
	public int unresolvedSectionId;
	public int bssSectionId;
	public long prologSectionOffset;
	public long epilogSectionOffset;
	public long unresolvedSectionOffset;
	
	public long sectionAlignment;
	public long bssSectionAlignment;
	public long fixSize;
	
	public SectionInfo[] sections;
	
	public RELHeader(BinaryReader reader) {
		this.readHeader(reader);
	}
	
	private void readHeader(BinaryReader reader) {
		try {
			reader.setPointerIndex(0);
			
			this.moduleId = reader.readNextUnsignedInt();
			this.previousModuleAddress = reader.readNextUnsignedInt();
			this.nextModuleAddress = reader.readNextUnsignedInt();
			this.sectionCount = reader.readNextUnsignedInt();
			this.sectionTableOffset = reader.readNextUnsignedInt();
			this.moduleNameOffset = reader.readNextUnsignedInt();
			this.moduleNameLength = reader.readNextUnsignedInt();
			this.moduleVersion = reader.readNextUnsignedInt();
			this.bssSize = reader.readNextUnsignedInt();
			this.relocationTableOffset = reader.readNextUnsignedInt();
			this.importTableOffset = reader.readNextUnsignedInt();
			this.importTableSize = reader.readNextUnsignedInt();
			this.prologSectionId = reader.readNextUnsignedByte();
			this.epilogSectionId = reader.readNextUnsignedByte();
			this.unresolvedSectionId = reader.readNextUnsignedByte();
			this.bssSectionId = reader.readNextUnsignedByte();
			this.prologSectionOffset = reader.readNextUnsignedInt();
			this.epilogSectionOffset = reader.readNextUnsignedInt();
			this.unresolvedSectionOffset = reader.readNextUnsignedInt();
			
			// Version specific settings
			if (this.moduleVersion > 1) {
				this.sectionAlignment = reader.readNextUnsignedInt();
				this.bssSectionAlignment = reader.readNextUnsignedInt();
			}
			else {
			    // Version 1's default values for alignment
			    this.sectionAlignment = 32;
			    this.bssSectionAlignment = 32;
			}
			
			if (this.moduleVersion > 2) {
				this.fixSize = reader.readNextUnsignedInt();
			}
			
			// Only read the sections if the header is valid.
			if (IsValid(reader)) {
				// Read sections info.
				reader.setPointerIndex(this.sectionTableOffset);
				this.sections = new SectionInfo[(int) this.sectionCount];
				for (var i = 0; i < this.sectionCount; i++) {
					this.sections[i] = new SectionInfo(reader.readNextUnsignedInt(), reader.readNextUnsignedInt());
				}
			}
		}
		catch (IOException e) {
			Msg.error(this,  "Failed to read REL header!");
		}
	}
	
	public boolean IsValid(BinaryReader reader) {
		try {
			long fileSize = reader.length();

			// Check section info is valid first.
			if (this.sectionTableOffset > fileSize) {
				Msg.error(this, "Unable to load REL file! Reason: Section Info Table address is past file bounds!");
				return false;
			}
			
			// Check that the relocation data offset & import info offset are valid offsets in the file.
			if (this.relocationTableOffset >= fileSize) {
				Msg.error(this, "Unable to load REL file! Reason: Relocation Data offset in header is past the file bounds!");
				return false;
			}
			
			if (this.importTableOffset + this.importTableSize > fileSize) {
				Msg.error(this, "Unable to load REL file! Reason: Import Table offset + Import Table size in header is past the file bounds!");
				return false;
			}
			
			long sectionTableSize = this.sectionCount * SectionInfo.SECTION_INFO_SIZE;
			
			// Get the first section address by file address.
			long firstSectionInFileAddress = -1;
			reader.setPointerIndex(this.sectionTableOffset);
			
			for (int i = 0; i < this.sectionCount; i++) {
				long sectionAddress = reader.readNextUnsignedInt() & ~1; // Clear the executable bit-flag.
				long sectionSize = reader.readNextUnsignedInt();
				
				if (sectionAddress != 0 && sectionSize != 0 && sectionSize != this.bssSize) {
					if (firstSectionInFileAddress == -1 || sectionAddress < firstSectionInFileAddress) {
						firstSectionInFileAddress = sectionAddress;
					}
				}
			}
			
			// Ensure that the section table offset doesn't intersect the first section's data.
			if (this.sectionTableOffset + sectionTableSize > firstSectionInFileAddress) {
				Msg.error(this, "Unable to load REL file! Reason: Section Info Table intersects section data!");
				return false;
			}
			
			// TODO: Ensure that no section intersects with another. Should this include the relocation data section & import info section?
		}
		catch (IOException e) {
			return false;
		}
		
		return true;
	}
	
	public int Size() {
		switch ((int) this.moduleId) {
		case 0:
		case 1:
			return 0x40;
		
		case 2:
			return 0x48;
		
		case 3:
		default:
			return 0x4C; 
		}
	}
}
