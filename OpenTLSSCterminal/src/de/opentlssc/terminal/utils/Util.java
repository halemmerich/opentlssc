package de.opentlssc.terminal.utils;


import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * This class contains various utilities useful while JavaCard development
 * 
 * @author Martin Boonk
 *
 */
public class Util {

	private static int columns = 16;
	private static int divides = 8;

	public static final String directionCard = "C--> ";
	public static final String directionTerminal = "C<-- ";
	public static final String directionDummy = "     ";

	public static final String HEX_PREFIX = "0x";
	public static final String BIN_PREFIX = "0b";
	
	public static String printLine(int length){
		String result = "";
		for (int i = 0; i < length; i++){
			result += "-";
		}
		return result;
	}
	
	public static String byteArrayToTabular(byte[] bytes) {
		return byteArrayToTabular(bytes, "");
	}

	public static String byteArrayToTabular(byte[] a, String spacer) {
		return byteArrayToTabular(a, spacer, 0, a.length);
	}

	public static String byteArrayToTabular(byte[] a, String spacer,
			int offset, int length) {
		List<List<Byte>> table = new ArrayList<List<Byte>>();
		int widthOfAHex = 4;
		String linenumberdummy = "_____";

		StringBuilder sb = new StringBuilder();

		List<Byte> current = null;
		for (int i = offset; i < length + offset; i++) {
			if ((i - offset) % columns == 0) {
				current = new ArrayList<Byte>();
				table.add(current);
			}
			current.add(a[i]);
		}

		if (table.size() > 1) {
			sb.append(spacer + linenumberdummy + "|_");
			for (int i = 0; i < columns / divides; i++) {
				// sb.append(String.format("%-3d", i * divides));
				String number = "" + i * divides;
				sb.append(number);
				for (int j = number.length(); j < widthOfAHex; j++) {
					sb.append("_");
				}
				for (int j = 0; j < divides - 1; j++) {
					sb.append("_____");
				}

				sb.append("_");
			}
			sb.append("|");
			for (int i = 0; i < columns / divides; i++) {
				// sb.append(String.format("%01d", i * divides));
				String number = "" + i * divides;
				sb.append(number);
				for (int j = number.length(); j < divides; j++) {
					sb.append("_");
				}
				/*
				 * for (int j = 0; j < divides - 1; j++) { sb.append("_"); }
				 */
			}
			sb.append("|");
			sb.append(System.lineSeparator());
		}
		for (int j = 0; j < table.size(); j++) {
			if (j != 0) {
				sb.append(System.lineSeparator());
			}

			sb.append(spacer
					+ String.format("%" + (linenumberdummy.length() - 1) + "d",
							j) + " | ");
			for (int i = 0; i < columns; i++) {
				if (i < table.get(j).size()) {
					sb.append(Util.toHex(table.get(j).get(i)) + " ");
				} else {
					sb.append(".... ");
				}
			}

			sb.append("|");
			for (int i = 0; i < table.get(j).size(); i++) {
				char c = (char) (byte) table.get(j).get(i);
				if (c >= 0x20 && c <= 0x7e) {
					sb.append(c);
				} else {
					sb.append(" ");
				}
			}
			sb.append("|");
		}
		return sb.toString();
	}

	public static String byteArrayToString(byte[] a) {
		return byteArrayToString(a, 0, a.length, HEX_PREFIX, " ");
	}

	public static String byteArrayToString(byte[] a, int offset, int length) {
		return byteArrayToString(a, offset, length, HEX_PREFIX, " ");
	}

	public static String byteArrayToString(byte[] a, int offset, int length, String prefix,
			String seperator) {
		StringBuilder sb = new StringBuilder();
		for (int i = offset; i < offset + length; i++) {
			sb.append(toHex(a[i], prefix));
			if (i < offset + length - 1) {
				sb.append(seperator);
			}
		}
		return sb.toString();

	}

	public static String toBinary(byte b) {
		return toBinary(b, BIN_PREFIX);
	}

	public static String toBinary(byte b, String prefix) {
		String result = "";
		for (int i = 0; i < 8; i++) {
			result += (b >>> (7 - i)) & (0x01);
		}
		return result;
	}
	
	public static String toBinary(short s, String prefix) {
		String result = toBinary((byte) (s >>> 8), "");
		result += toBinary((byte) (s), "");
		return prefix + result;
	}

	public static String toHex(byte b) {
		return toHex(b, HEX_PREFIX);
	}

	public static String toHex(byte b, String prefix) {
		return prefix + String.format("%02x", b);
	}

	public static String toHex(short s) {
		return toHex(s, HEX_PREFIX);
	}

	public static String toHex(short s, String prefix) {
		return prefix + String.format("%04x", s);
	}

	public static String printCommandApduTabular(CommandAPDU c) {
		return printCommandApduTabular(c, "");
	}

	public static String printCommandApduTabular(CommandAPDU c, String spacer) {
		String result = printCommandApduMeta(c, spacer);
		if (c.getData().length > 0) {
			result += System.lineSeparator()
					+ printDataTabular(c.getData(), spacer + directionCard);
		}
		return result;

	}

	public static String printCommandApduMeta(CommandAPDU c) {
		return printCommandApduMeta(c, "");
	}

	public static String printCommandApduMeta(CommandAPDU c, String spacer) {
		spacer += directionCard;
		short p1p2 = (short) (((c.getP1() & 0xFF) << 8) | (c.getP2() & 0xFF));
		String result = spacer + "Command CLA:" + Util.toHex((byte) c.getCLA())
				+ "(" + c.getCLA() + ")" + " INS:"
				+ Util.toHex((byte) c.getINS()) + "(" + c.getINS() + ")"
				+ " P1:" + Util.toHex((byte) c.getP1()) + "(" + c.getP1() + ")"
				+ " P2:" + Util.toHex((byte) c.getP2()) + "(" + c.getP2() + ")"
				+ " P1P2:" + Util.toHex(p1p2) + "(" + p1p2 + ")" + " NC: "
				+ c.getNc() + " NE: " + c.getNe() + System.lineSeparator();

		int ne;
		int nc;

		if (c.getNc() > 256 && c.getNe() > 256) {
			// case 4E
			nc = 3;
			ne = 2;
		} else if (c.getNc() > 0 && c.getNc() < 256 && c.getNe() < 256
				&& c.getNe() > 0) {
			// case 4S
			ne = 1;
			nc = 1;
		} else if (c.getNc() > 255 && c.getNe() == 0) {
			// case 3S
			nc = 3;
			ne = 0;
		} else if (c.getNc() < 256 && c.getNc() > 0 && c.getNe() == 0) {
			// case 3E
			nc = 1;
			ne = 0;
		} else if (c.getNc() == 0 && c.getNe() > 255) {
			// case 2E
			nc = 0;
			ne = 2;
		} else if (c.getNc() == 0 && c.getNe() > 0 && c.getNe() < 256) {
			// case 2S
			ne = 1;
			nc = 0;
		} else {
			// case 1
			ne = 0;
			nc = 0;
		}

		int headerLength = 4 + nc;
		int trailerOffset = c.getBytes().length - ne;

		result += spacer + "Header:" + System.lineSeparator()
				+ byteArrayToTabular(c.getBytes(), spacer, 0, headerLength);
		if (ne > 0) {
			result += System.lineSeparator() + spacer + "Trailer: ";
			if (ne == 1) {
				short trailer = c.getBytes()[trailerOffset];
				result += toHex((byte) trailer) + " (" + trailer + ")";
			} else {
				short trailer = getShort(c.getBytes(), trailerOffset);
				result += toHex(trailer) + " (" + trailer + ")";
			}
		}
		return result;
	}

	public static String printResponseApduTabular(ResponseAPDU r) {
		return printResponseApduTabular(r, "");
	}

	public static String printResponseApduTabular(ResponseAPDU r, String spacer) {

		if (r != null) {
			String result = printResponseApduMeta(r, spacer);
			if (r.getData().length > 0) {
				result += System.lineSeparator()
						+ printDataTabular(r.getData(), spacer
								+ directionTerminal);
			}
			return result + System.lineSeparator();
		}
		return "";
	}

	public static String printResponseApduMeta(ResponseAPDU r) {
		return printResponseApduMeta(r, "");
	}

	public static String printResponseApduMeta(ResponseAPDU r, String spacer) {
		return spacer + directionTerminal + "Response SW: "
				+ toHex((short) r.getSW());
	}

	public static String printDataTabular(byte[] data, String spacer) {
		return spacer + "Data (" + data.length + " byte):"
				+ System.lineSeparator() + byteArrayToTabular(data, spacer);
	}

	public static String printApdusTabular(CommandAPDU c, ResponseAPDU r) {
		return printApdusTabular(c, r, "");
	}

	public static String printApdusTabular(CommandAPDU c, ResponseAPDU r,
			String spacer) {
		return printCommandApduTabular(c, spacer) + System.lineSeparator()
				+ printResponseApduTabular(r, spacer);
	}
	
	public static String printTime(long time) {
		return printTime(time, "");
	}
	
	public static String printTime(long time, String spacer){
		long minutes, seconds, milliseconds;
		minutes = (time / 1000) / 60;
		seconds = (time - minutes * 1000 * 60) / 1000;
		milliseconds = (time - seconds * 1000 - minutes * 1000 * 60);

		String result = directionDummy + spacer + "Time: ";
		result += String.format("%02d", minutes) + ":";
		result += String.format("%02d", seconds) + ".";
		result += String.format("%03d", milliseconds);
		return result;
	}

	public static void arrayCopy(byte[] in, int inOff, int length, byte[] out,
			int outOff) {
		for (int i = inOff; i < inOff + length; i++) {
			out[outOff + i - inOff] = in[i];
		}
	}

	public static int unsignedUpcast(short s) {
		return s & 0xFFFF;
	}

	public static int unsignedUpcast(byte b) {
		return b & 0xFF;
	}

	public static short getShort(byte[] src, int off) {
		return (short) (((src[off] << 8) & 0x0000FF00) | (src[off + 1] & 0x000000FF));
	}

	public static void setShort(byte[] dest, int off, int value) {
		dest [off] = (byte) ((value & 0x0000FF00) >>> 8);
		dest [off +1] = (byte) (value & 0x0000FF);
	}

	public static String printBinary(short s) {
		return toBinary(s, BIN_PREFIX);
	}

	public static byte[] to3Bytes(int input) {
		byte[] result = new byte[3];
		result[0] = (byte) input;
		result[1] = (byte) (input >>> 8);
		result[2] = (byte) (input >>> 16);
		return result;
	}

	public static byte[] toPrimitiveArray(Byte[] in) {
		byte[] result = new byte[in.length];
		for (int i = 0; i < in.length; i++) {
			result[i] = in[i];
		}
		return result;
	}

	public static byte[] toPrimitiveArray(List<Byte> in) {
		byte[] result = new byte[in.size()];
		for (int i = 0; i < in.size(); i++) {
			result[i] = in.get(i);
		}
		return result;
	}

	public static List<Byte> fromPrimitiveArray(byte[] in) {
		List<Byte> result = new ArrayList<Byte>();
		for (byte b : in) {
			result.add(b);
		}
		return result;
	}

	public static Byte[] fromPrimitiveArrayToWrapper(byte[] in) {
		Byte[] result = new Byte[in.length];
		for (int i = 0; i < result.length; i++) {
			result[i] = in[i];
		}
		return result;
	}

}
