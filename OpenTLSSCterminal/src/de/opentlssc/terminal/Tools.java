package de.opentlssc.terminal;


public class Tools {

	public static byte[] concatByteArrays(byte[]... arrays) {
		int length = 0;
		for (byte[] b : arrays) {
			length += b.length;
		}
		byte[] result = new byte[length];
		int off = 0;
		for (byte[] b : arrays) {
			for (int i = 0; i < b.length; i++) {
				result[i + off] = b[i];
			}
			off += b.length;
		}
		return result;
	}
}
