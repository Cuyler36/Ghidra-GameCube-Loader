package gamecubeloader.rso;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Stream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class RSOModule implements AutoCloseable {
    public static final class ExportSymbol {
        public final long strOffset;
        public final long value;
        public final long section;
        public final long hash;

        public final String name;

        public ExportSymbol(BinaryReader reader, long exportStrOffset) throws IOException {
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

    public static final class ImportSymbol {
        public final long strOffset;
        public final long value;
        public final long relOffset;

        public final String name;

        public ImportSymbol(BinaryReader reader, long importStrOffset) throws IOException {
            strOffset = reader.readNextUnsignedInt();
            value = reader.readNextUnsignedInt();
            relOffset = reader.readNextUnsignedInt();

            long pos = reader.getPointerIndex();
            reader.setPointerIndex(importStrOffset + strOffset);
            name = reader.readNextAsciiString();
            reader.setPointerIndex(pos);
        }
    }

    public static final class Relocation {
        public static final int SIZE = 4 * 3;

        public final long offset;
        public final long info;
        public final long addend;


        public Relocation(BinaryReader reader) throws IOException {
            offset = reader.readNextUnsignedInt();
            info = reader.readNextUnsignedInt();
            addend = reader.readNextUnsignedInt();
        }

        public int getSectionIndex() {
            return (int) ((info >> 8) & 0xFFFFFF);
        }

        public int getSymbolIndex() {
            return getSectionIndex();
        }

        public short getRelocationType() {
            return (short) (info & 0xFF);
        }
    }

    private static final int IMP_TABLE_SIZE = 12;
    private static final int EXP_TABLE_SIZE = 16;

    private final ByteProvider provider;
    private final BinaryReader reader;

    private final List<Relocation> internalRelocations;
    private final List<Relocation> externalRelocations;

    private HashMap<Long, ArrayList<ExportSymbol>> exports;
    private ArrayList<ImportSymbol> imports;

    public final RSOHeader header;

    public RSOModule(RSOHeader header, ByteProvider provider) throws IOException {
        this.provider = provider;
        this.header = header;
        this.reader = new BinaryReader(provider, false);

        this.internalRelocations = parseRelocations(this.header.internalRelOffset, this.header.internalRelSize);
        this.externalRelocations = parseRelocations(this.header.externalRelOffset, this.header.externalRelSize);

        parseExports();
        parseImports();
    }

    public static long getHash(String symbolName) {
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

    public int getNumExportSymbols() {
        return (int)header.exportSymbolTableSize / EXP_TABLE_SIZE;
    }

    private List<Relocation> parseRelocations(long relocationTable, long relocationSize) throws IOException {
        var relocations = new ArrayList<Relocation>();
        var prevPos = reader.getPointerIndex();

        reader.setPointerIndex(relocationTable);
        var relocationCount = relocationSize / Relocation.SIZE;
        for (var i = 0; i < relocationCount; ++i) {
            relocations.add(new Relocation(reader));
        }

        reader.setPointerIndex(prevPos);
        return relocations;
    }

    private void parseExports() throws IOException {
        exports = new HashMap<>();

        final int numExports = getNumExportSymbols();
        var exportOffset = header.exportSymbolTableOffset;
        reader.setPointerIndex(exportOffset);
        for (var i = 0; i < numExports; ++i) {
            var sym = new ExportSymbol(reader, header.exportSymbolNamesOffset);
            var exportSymbols = exports.computeIfAbsent(sym.hash, k -> new ArrayList<>());
            exportSymbols.add(sym);
        }
    }

    private void parseImports() throws IOException {
        imports = new ArrayList<>();
        final int numImports = getNumImportSymbols();
        reader.setPointerIndex(header.importSymbolTableOffset);
        for (var i = 0; i < numImports; ++i) {
            imports.add(new ImportSymbol(reader, header.importSymbolNamesOffset));
        }
    }

    public ExportSymbol getExportSymbolFromName(final String name) {
        var hash = getHash(name);

        var exportSymbols = exports.getOrDefault(hash, null);
        if (exportSymbols == null) {
            return null;
        }

        for (var sym : exportSymbols) {
            if (sym.name.equals(name)) {
                return sym;
            }
        }

        return null;
    }

    public int getNumImportSymbols() {
        return (int)header.importSymbolTableSize / IMP_TABLE_SIZE;
    }

    public BinaryReader getReader() {
        return reader;
    }

    public ByteProvider getProvider() {
        return provider;
    }

    public List<Relocation> getInternalRelocations() {
        return internalRelocations;
    }

    public List<Relocation> getExternalRelocations() {
        return externalRelocations;
    }

    public Stream<ExportSymbol> getExportSymbols() {
        return exports.values().stream().flatMap(Collection::stream);
    }
    public List<ImportSymbol> getImportSymbols() {
        return imports;
    }

    @Override
    public void close() throws IOException {
        provider.close();
    }
}
