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
class ASN1Tools{
	
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
		short length = getNumberOfIdentifierOctets(buffer, offset);
		short tag = parseIdentifierOctets(buffer, offset, length);
		short numberOfLengthOctets= getNumberOfLengthOctets(buffer, (short) (offset + length));
		length += parseLengthOctets(buffer, (short) (offset + length), numberOfLengthOctets);
		length += numberOfLengthOctets;
		length += getNumberOfAdditionalNonContentOctets(tag);
		return length;
	}
	
	static short getContentLength(byte [] buffer, short offset){
		offset += getNumberOfIdentifierOctets(buffer, offset);
		short numberOfLengthOctets= getNumberOfLengthOctets(buffer, offset);
		return parseLengthOctets(buffer, offset, numberOfLengthOctets);
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
		short numberOfIdentifierOctets = getNumberOfIdentifierOctets(data, offset);
		short tag = parseIdentifierOctets(data, offset, numberOfIdentifierOctets);
		offset += numberOfIdentifierOctets;
		offset += getNumberOfLengthOctets(data, offset);
		return offset += getNumberOfAdditionalNonContentOctets(tag);
	}
	
	static short getNumberOfIdentifierOctets(byte [] data, short offset){
		short tag = (short) (data[offset] & 0x1F);
		
		//mask the last 5 bits
		short numberOfIdentifierOctets = 1;
		//if identifier octet is 00011111 read further octets
		if (tag == 0x1F) {
			while (checkSingleBit(data[(short) (offset + numberOfIdentifierOctets - 1)], (short) 7)) {
				numberOfIdentifierOctets++;
			}
		}
		return numberOfIdentifierOctets;
	}
	
	static short getNumberOfAdditionalNonContentOctets(short tag){
		switch (tag){
		case 3:
			//BITSTRING, contains 1 byte information about used bits in last octet
			return 1;
		default:
			return 0;
		} 
	}
	
	static short getNumberOfLengthOctets(byte [] data, short offset){
		// if bit 7 set long form
		// if not short form
		short numberOfLengthOctets = 1;
		if (checkSingleBit(data[offset], (short) 7)) {
			numberOfLengthOctets += (short) ((data[(short) (offset)] & 0x7F));
		}
		return numberOfLengthOctets;
	}
	
	/**
	 * Parse the structure at the given offset and return its length.
	 * 
	 * @param data
	 * @param offset
	 * @return
	 */
	static short jumpOver(byte[] data, short offset) {
		return (short) (offset + getLengthOfStructure(data, offset));
	}

	


	/**
	 * Parses ASN.1 length octets
	 * 
	 * @param data
	 * @param offset
	 *            to the first length octet
	 * @return length value as short
	 */
	static short parseLengthOctets(byte[] data, short offset, short numberOfLengthOctets) {
		// if bit 7 set long form
		// if not short form
		short length = 0;
		if (numberOfLengthOctets > 1) {
			length = (short) ((data[(short) (offset)] & 0x7F) + 1);
			for (short i = 1; i < numberOfLengthOctets; i++) {
				length |= data[(short) (offset + i)] & 0xFF;
				if (i < (short) (numberOfLengthOctets - 1)) {
					length <<= 8;
				}
			}
		} else {
			length = data[offset];
		}
		return length;
	}

	/**
	 * updates lastNumberOfIdentifierOctets
	 * 
	 * @param data
	 * @param offset
	 *            to the first identifier octet
	 * @return tag number
	 */
	static short parseIdentifierOctets(byte[] data, short offset, short numberOfIdentifierOctets) {
		
		short tag = 0;
		if (numberOfIdentifierOctets > 1) {
			tag = 0;
			for (short i = 1; i < numberOfIdentifierOctets; i++){
				tag |= data[(short) (offset + i)] & 0x7F;
			}
		} else {
			tag = (short) (data[offset] & 0x1F);
		}
		return tag;
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
