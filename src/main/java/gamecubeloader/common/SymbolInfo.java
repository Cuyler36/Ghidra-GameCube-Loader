package gamecubeloader.common;

public final class SymbolInfo {
	public String name;
	public String container;
	public long startingAddress;
	public long size;
	public long virtualAddress;
	public int alignment;
	public boolean isSubEntry;
	
	public SymbolInfo(String name, String container, long startingAddress, long size,
			long virtualAddress, int alignment, boolean isSubEntry) {
		this.name = name;
		this.container = container;
		this.startingAddress = startingAddress;
		this.size = size;
		this.virtualAddress = virtualAddress;
		this.alignment = alignment;
		this.isSubEntry = isSubEntry;
	}
}
