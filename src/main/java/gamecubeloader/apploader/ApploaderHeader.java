package gamecubeloader.apploader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public final class ApploaderHeader {
	public static final int HEADER_SIZE = 32;
	
	private String revision;
	private long entryPoint;
	private int size;
	private int trailerSize;
	
	private long fileSize;
	
	public ApploaderHeader(BinaryReader reader) {
		this.readHeader(reader);
	}
	
	private void readHeader(BinaryReader reader) {
		try {
			fileSize = reader.length();
			reader.setPointerIndex(0);
			
			revision = reader.readNextAsciiString(16);
			entryPoint = reader.readNextUnsignedInt();
			size = reader.readNextInt();
			trailerSize = reader.readNextInt();
		}
		catch(IOException e) {
			Msg.error(this, "Failed to read Apploader header!");
		}
	}
	
	public boolean IsValid() {
		if (size == 0)
			return false;
		if (entryPoint - 0x81200000L < ApploaderHeader.HEADER_SIZE)
			return false;
		if (entryPoint - 0x81200000L >= fileSize)
			return false;
		if (size + trailerSize + ApploaderHeader.HEADER_SIZE > fileSize)
			return false;
		return true;
	}
	
	public String GetRevision() {
		return revision;
	}
	
	public long GetEntryPoint() {
		return entryPoint;
	}
	
	public int GetSize() {
		return size;
	}
	
	public int GetTrailerSize() {
		return trailerSize;
	}
}
