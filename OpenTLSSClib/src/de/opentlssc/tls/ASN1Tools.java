// Copyright 2013 Martin Boonk
//
// This file is part of the OpenTLSSClib.
//
// The OpenTLSSClib is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The OpenTLSSClib is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the OpenTLSSClib.  If not, see <http://www.gnu.org/licenses/>.

package de.opentlssc.tls;


/**
 * A set of tools to parse ASN1 structures as used in X.509 certificates.
 * 
 * @author Martin Boonk
 *
 */
class ASN1Tools extends StaticTool{

	static short			lastNumberOfIdentifierOctets;
	static short			lastNumberOfLengthOctets;
	static short			lastNumberOfAdditionalNonContentOctets;
	static short			lastHeaderLength;

	/**
	 * Get length including length of identifier and length octets
	 * <p>
	 * 
	 * updates lastNumberOfIdentifierOctets and lastNumberOfLengthOctets
	 * 
	 * @param buffer
	 * @param offset
	 * @return
	 */
	static short getLengthOfStructure(byte[] buffer, short offset) {

		//byte cla = (byte) (buffer[offset] >>> 6);
		short length = 0;
		parseIdentifierOctets(buffer, offset);
		length += lastNumberOfIdentifierOctets;
		// check class
		// if (cla == CLASS_UNIVERSAL) {
		length += parseLengthOctets(buffer, (short) (offset + length));
		length += lastNumberOfLengthOctets;
		// }
		length += lastNumberOfAdditionalNonContentOctets;
		return length;
	}


	/**
	 * Parse the structure at the given offset and return its length.
	 * 
	 * @param data
	 * @param offset
	 * @return
	 */
	static short jumpOver(byte[] data, short offset) {
		return getLengthOfStructure(data, offset);
	}

	
	/**
	 * Parse the structure at the given offset and return the offset to its content.
	 * 
	 * @param data
	 * @param offset
	 * @return
	 */
	static short jumpInto(byte[] data, short offset) {
		// if (!checkSingleBit(data[offset], (short) 5)) {
		// CardRuntimeException.throwIt(Exceptions.ASN1_JUMP_INTO_PRIMITIVE);
		// }
		getLengthOfStructure(data, offset);
		return (short) (lastNumberOfIdentifierOctets + lastNumberOfLengthOctets + lastNumberOfAdditionalNonContentOctets);
	}

	/**
	 * Parses ASN.1 length octets
	 * 
	 * @param data
	 * @param offset
	 *            to the first length octet
	 * @return length value as short
	 */
	static short parseLengthOctets(byte[] data, short offset) {

		short result = 0;
		// if bit 7 set long form
		// if not short form
		if (checkSingleBit(data[offset], (short) 7)) {
			lastNumberOfLengthOctets = (short) ((data[(short) (offset)] & 0x7F) + 1);
			for (short i = 1; i < lastNumberOfLengthOctets; i++) {
				result |= data[(short) (offset + i)] & 0xFF;
				if (i < (short) (lastNumberOfLengthOctets - 1)) {
					result <<= 8;
				}
			}
		} else {
			result = data[offset];
			lastNumberOfLengthOctets = 1;
		}
		return result;
	}

	/**
	 * updates lastNumberOfIdentifierOctets
	 * 
	 * @param data
	 * @param offset
	 *            to the first identifier octet
	 * @return tag number
	 */
	static short parseIdentifierOctets(byte[] data, short offset) {
		//mask the last 5 bits
		short result = (short) (data[offset] & 0x1F);
		lastNumberOfIdentifierOctets = 1;
		//if identifier octet is 00011111 read further octets
		if (result == 0x1F) {
			result = 0;
			while (checkSingleBit(data[(short) (offset + result)], (short) 7)) {
				result |= data[(short) (offset + lastNumberOfIdentifierOctets - 1)] & 0xFF;
				lastNumberOfIdentifierOctets++;
			}
		}
		switch (result){
		case 3:
			//BITSTRING, contains 1 byte information about used bits in last octet
			lastNumberOfAdditionalNonContentOctets = 1;
			break;
		default:
			lastNumberOfAdditionalNonContentOctets = 0;
		}
		return result;
	}

	/**
	 * Check if a specific bit is set.
	 * 
	 * @param data
	 * @param bit
	 * @return
	 */
	private static boolean checkSingleBit(byte data, short bit) {
		byte test = (byte) ((data & 0xFF) >>> bit);
		return test == 1;
	}
}
