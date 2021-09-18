package gamecubeloader.rso;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class RSO {
    private final class RSOExportSymbol {
        public final long strOffset;
        public final long value;
        public final long section;
        public final long hash;
        
        public final String name;
        
        public RSOExportSymbol(BinaryReader reader, long exportStrOffset) throws IOException {
            strOffset = reader.readNextUnsignedInt();
            value = reader.readNextUnsignedInt();
            section = reader.readNextUnsignedInt();
            hash = reader.readNextUnsignedInt();
            
            long pos = reader.getPointerIndex();
            reader.setPointerIndex(exportStrOffset + strOffset);
            name = reader.readNextAsciiString();
            reader.setPointerIndex(pos);
        }
    }
    
    private final class RSOImportSymbol { 
        public final long strOffset;
        public final long value;
        public final long relOffset;
        
        public RSOImportSymbol(BinaryReader reader) throws IOException { 
            strOffset = reader.readNextUnsignedInt();
            value = reader.readNextUnsignedInt();
            relOffset = reader.readNextUnsignedInt();
        }
    }
    
    private static final int IMP_TABLE_SIZE = 12;
    private static final int EXP_TABLE_SIZE = 16;
    
    private ByteProvider provider;
    private BinaryReader reader;
    private HashMap<Long, ArrayList<RSOExportSymbol>> exports;
    
    public RSOHeader header;
    
    public RSO(ByteProvider provider) throws IOException {
        this.provider = provider;
        reader = new BinaryReader(provider, false);
        
        ParseExports();
    }
    
    public static long GetHash(String symbolName) {
        long hash = 0;
        for (int i = 0; i < symbolName.length(); i++) {
            long mod = (hash << 4) + symbolName.charAt(i);
            long negate = mod & 0xF0000000;
            if (negate != 0)
                mod ^= negate >> 24;
            hash = mod & ~negate;
        }
        return hash;
    }
    
    public int GetNumExportSymbols() {
        return (int)header.exportSymbolTableSize / EXP_TABLE_SIZE;
    }
    
    private void ParseExports() throws IOException {
        exports = new HashMap<Long, ArrayList<RSOExportSymbol>>();
        
        final int num_exports = GetNumExportSymbols();
        long export_offset = header.exportSymbolTableOffset;
        reader.setPointerIndex(export_offset);
        for (int i = 0; i < num_exports; i++) {
            RSOExportSymbol sym = new RSOExportSymbol(reader, header.exportSymbolNamesOffset);
            if (!exports.containsKey(sym.hash)) {
                exports.put(sym.hash, new ArrayList<RSOExportSymbol>());
            }
            
            exports.get(sym.hash).add(sym);
        }
    }
    
    public RSOExportSymbol GetExportSymbolFromName(final String name) {
        long hash = GetHash(name);
        if (exports.containsKey(hash)) {
            for (RSOExportSymbol sym : exports.get(hash)) {
                if (sym.name.equals(name)) {
                    return sym;
                }
            }
        }
        return null;
    }
    
    public int GetNumImportSymbols() {
        return (int)header.importSymbolTableSize / IMP_TABLE_SIZE;
    }
    
    public void Link(final RSO exporter) throws IOException {
        final int numImports = GetNumImportSymbols();
        long impOfs = header.importSymbolTableOffset;
        for (int i = 0; i < numImports; i++) {
            long nameOfs = reader.readUnsignedInt(impOfs);
            
            impOfs += IMP_TABLE_SIZE;
        }
    }
    
    public BinaryReader getReader() {
        return reader;
    }
}
