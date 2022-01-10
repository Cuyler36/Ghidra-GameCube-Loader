package gamecubeloader.common;

public class SectionInfo {
    public static final int SECTION_INFO_SIZE = 8;

    public long address;
    public long size;

    public SectionInfo(long address, long size) {
        this.address = address;
        this.size = size;
    }
}