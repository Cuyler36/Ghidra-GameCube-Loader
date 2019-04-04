package gamecubeloader.common;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

public class Yaz0 {
	public boolean IsValid(ByteProvider provider) throws IOException {
		return new String(provider.readBytes(0, 4)).equals("Yaz0");
	}

	public ByteProvider Decompress(ByteProvider provider) throws IOException {
		var reader = new BinaryReader(provider, false);
		int decompressedSize = reader.readInt(4);
		byte[] decompressBuffer = new byte[decompressedSize];
		
		int readPosition = 0x10;
		int sourceBitfield = 0;
		int writePosition = 0;
		int sourceByte = 0;
		
		do {
			int localReadPosition = readPosition;
			
			if (sourceBitfield == 0) {
				sourceByte = reader.readUnsignedByte(readPosition);
				sourceBitfield = 0x80;
				localReadPosition = readPosition + 1;
			}
			
			if ((sourceByte & sourceBitfield) == 0) {
				readPosition = localReadPosition + 2;
				
				int bitInfo = reader.readUnsignedShort(localReadPosition);
				int bitAdjustReadOffset = writePosition - (bitInfo & 0x0FFF);
				int writeSize;
				
				if ((bitInfo >> 12) == 0) {
					writeSize = reader.readUnsignedByte(readPosition) + 0x12;
					readPosition = localReadPosition + 3;
				}
				else {
					writeSize = ((bitInfo >> 12) & 0xF) + 2;
				}
				
				while (writeSize != 0) {
					decompressBuffer[writePosition] = decompressBuffer[bitAdjustReadOffset - 1];
					writePosition++;
					bitAdjustReadOffset++;
					writeSize--;
				}
			}
			else {
				readPosition = localReadPosition + 1;
				decompressBuffer[writePosition] = (byte)reader.readUnsignedByte(localReadPosition);
				writePosition++;
			}
			
			sourceBitfield >>= 1;
		} while (writePosition < decompressedSize);
		
		return new ByteArrayProvider(decompressBuffer);
	}
}
