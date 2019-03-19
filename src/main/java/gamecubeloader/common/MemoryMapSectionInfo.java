package gamecubeloader.common;

public final class MemoryMapSectionInfo {
	public String name;
	public long startingAddress;
	public long size;
	public long fileOffset;
	
	public MemoryMapSectionInfo(String name, long startingAddress, long size, long fileOffset) {
		this.name = name;
		this.startingAddress = startingAddress;
		this.size = size;
		this.fileOffset = fileOffset;
	}
}
