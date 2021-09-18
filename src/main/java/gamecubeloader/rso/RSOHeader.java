package gamecubeloader.rso;

public class RSOHeader {
    public class SectionInfo {
        public long address;
        public long size;
        
        public SectionInfo(long address, long size) {
            this.address = address;
            this.size = size;
        }
    }
    
    public long next;
    public long prev;
    public long numSections;
    public long sectionInfoOffset;
    
    public long nameOffset;
    public long nameSize;
    public long version; // RSO Version
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
}
