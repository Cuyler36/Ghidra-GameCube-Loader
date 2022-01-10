package gamecubeloader.rso;

import gamecubeloader.common.SectionInfo;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

import java.io.IOException;

public class RSOHeader {
    public static long HEADER_SIZE = 0x58;

    public long nextModule;
    public long prevModule;
    public long numSections;
    public long sectionInfoOffset;

    public long nameOffset;
    public long nameSize;
    public long version;
    public long bssSize;

    public int prologSection;
    public int epilogSection;
    public int unresolvedSection;
    public int bssSection;

    public long prologOffset;
    public long epilogOffset;
    public long unresolvedOffset;

    public long internalRelOffset;
    public long internalRelSize;

    public long externalRelOffset;
    public long externalRelSize;

    public long exportSymbolTableOffset;
    public long exportSymbolTableSize;
    public long exportSymbolNamesOffset;

    public long importSymbolTableOffset;
    public long importSymbolTableSize;
    public long importSymbolNamesOffset;

    public SectionInfo[] sections;

    public RSOHeader(BinaryReader reader) {
        this.readHeader(reader);
    }

    private void readHeader(BinaryReader reader) {
        try {
            reader.setPointerIndex(0);

            this.nextModule = reader.readNextUnsignedInt();
            this.prevModule = reader.readNextUnsignedInt();
            this.numSections = reader.readNextUnsignedInt();
            this.sectionInfoOffset = reader.readNextUnsignedInt();

            this.nameOffset = reader.readNextUnsignedInt();
            this.nameSize = reader.readNextUnsignedInt();
            this.version = reader.readNextUnsignedInt();
            this.bssSize = reader.readNextUnsignedInt();

            this.prologSection = reader.readNextUnsignedByte();
            this.epilogSection = reader.readNextUnsignedByte();
            this.unresolvedSection = reader.readNextUnsignedByte();
            this.bssSection = reader.readNextUnsignedByte();

            this.prologOffset = reader.readNextUnsignedInt();
            this.epilogOffset = reader.readNextUnsignedInt();
            this.unresolvedOffset = reader.readNextUnsignedInt();

            this.internalRelOffset = reader.readNextUnsignedInt();
            this.internalRelSize = reader.readNextUnsignedInt();

            this.externalRelOffset = reader.readNextUnsignedInt();
            this.externalRelSize = reader.readNextUnsignedInt();

            this.exportSymbolTableOffset = reader.readNextUnsignedInt();
            this.exportSymbolTableSize = reader.readNextUnsignedInt();
            this.exportSymbolNamesOffset = reader.readNextUnsignedInt();

            this.importSymbolTableOffset = reader.readNextUnsignedInt();
            this.importSymbolTableSize = reader.readNextUnsignedInt();
            this.importSymbolNamesOffset = reader.readNextUnsignedInt();

            // Only read the sections if the header is valid.
            if (IsValid(reader)) {
                // Read sections info.
                reader.setPointerIndex(this.sectionInfoOffset);
                this.sections = new SectionInfo[(int) this.numSections];
                for (var i = 0; i < this.numSections; i++) {
                    this.sections[i] = new SectionInfo(reader.readNextUnsignedInt(), reader.readNextUnsignedInt());
                }
            }
        } catch (IOException e) {
            Msg.error(this,  "Failed to read RSO header!");
        }
    }

    public boolean IsValid(BinaryReader reader) {
        try {
            long fileSize = reader.length();

            // Check section info is valid first.
            if (this.sectionInfoOffset > fileSize) {
                Msg.error(this, "Unable to load RSO file! Reason: Section Info Table address is past file bounds!");
                return false;
            }

            // Check that the internal relocation data offset is valid
            if (this.internalRelOffset >= fileSize) {
                Msg.error(this, "Unable to load RSO file! Reason: Internal Relocation Data offset in header is past the file bounds!");
                return false;
            }

            // Check that the external relocation data offset is valid
            if (this.externalRelOffset >= fileSize) {
                Msg.error(this, "Unable to load RSO file! Reason: External Relocation Data offset in header is past the file bounds!");
                return false;
            }

            if (this.importSymbolTableOffset + this.importSymbolTableSize > fileSize) {
                Msg.error(this, "Unable to load RSO file! Reason: Import Symbol Table offset + Import Symbol Table size in header is past the file bounds!");
                return false;
            }

            if (this.exportSymbolTableOffset + this.exportSymbolTableSize > fileSize) {
                Msg.error(this, "Unable to load RSO file! Reason: Export Symbol Table offset + Export Symbol Table size in header is past the file bounds!");
                return false;
            }
        }
        catch (IOException e) {
            return false;
        }

        return true;
    }
}
