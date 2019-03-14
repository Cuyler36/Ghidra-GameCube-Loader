package gamecubeloader;

import java.io.IOException;
import java.nio.ByteBuffer;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

public class Yaz0 {
	public boolean IsValid(ByteProvider provider) throws IOException {
		return new String(provider.readBytes(0, 4)) == "Yaz0";
	}
	
	public int GetSize(ByteProvider provider) throws IOException {
		return ByteBuffer.wrap(provider.readBytes(4, 4)).getInt();
	}
	
	public ByteProvider Decompress(ByteProvider provider) throws IOException {
		int decompressedSize = GetSize(provider);
		byte[] decompressBuffer = new byte[decompressedSize];
		
		int readPosition = 0x10;
		int sourceBitfield = 0;
		int writePosition = 0;
		int sourceByte = 0;
		
		while (writePosition < decompressedSize) {
			int localReadPosition = readPosition;
			
			if (sourceBitfield == 0) {
				sourceByte = provider.readByte(readPosition);
				sourceBitfield = 0x80;
				localReadPosition = readPosition + 1;
			}
			
			if ((sourceByte & sourceBitfield) == 0) {
				readPosition = localReadPosition + 2;
				
				int bitInfo = ByteBuffer.wrap(provider.readBytes(localReadPosition, 2)).getShort();
				int bitAdjustReadOffset = writePosition - (bitInfo & 0x0FFF);
				int writeSize;
				
				if ((bitInfo >> 0xC) == 0) {
					writeSize = provider.readByte(readPosition) + 0x12;
					readPosition = localReadPosition + 3;
				}
				else {
					writeSize = (bitInfo >> 0xC) + 2;
				}
				
				while (writeSize != 0) {
					decompressBuffer[writePosition++] = decompressBuffer[bitAdjustReadOffset - 1];
					bitAdjustReadOffset++;
					writeSize--;
				}
			}
			else {
				readPosition = localReadPosition + 1;
				decompressBuffer[writePosition++] = provider.readByte(localReadPosition);
			}
			
			sourceBitfield >>= 1;
		}
		
		return new ByteArrayProvider(decompressBuffer);
	}
}
