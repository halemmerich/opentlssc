package de.opentlssc.terminal.utils;


import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

public class Conversions {
	public static void printCode(byte[] b) {
		StringBuilder sb = new StringBuilder();
		sb.append("byte[] name = {");
		for (int i = 0; i < b.length; i++) {
			if (i % 5 == 0 && i != 0) {
				sb.append("\n");
			}
			sb.append("(byte) 0x" + String.format("%02X", b[i]));

			if (i < b.length - 1) {
				sb.append(", ");
			}
		}
		sb.append("};");
		System.out.print(sb.toString());
		
		StringSelection selection = new StringSelection(sb.toString());
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(selection, null);
	}

	/**
	 * Parse the bytes of a GnuTLS log formatted hex string.
	 * 
	 * @param s
	 * @return the bytes
	 */
	public static byte[] parseGnuTlsString(String s) {
		int resLen = s.length() / 2;
		byte[] result = new byte[resLen];
		for (int i = 0; i < resLen; i ++) {
			result[i] = (byte) (Short.parseShort(s.substring(i*2, i*2 + 2), 16));
		}
		return result;
	}


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
