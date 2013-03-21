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

import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

/**
 * Provides facilities to handle cryptographic operations.
 * 
 * @author Martin Boonk
 *
 */
class CryptoTools extends StaticTool {

	static RandomData				random;
	private static byte [] randomNumberWorkspace;

	static RSAPublicKey				serverPublicKey512;
	static RSAPublicKey				serverPublicKey1024;
	static RSAPublicKey				serverPublicKey2048;
	
	static void init(){
		try {
			MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
		} catch (Exception e){
			LibraryConfiguration.emu = true;
		}
		
		if (LibraryConfiguration.emu) {
			random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		} else {
			random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		}
		randomNumberWorkspace = new byte [1];

		serverPublicKey512 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		if (!LibraryConfiguration.emu){
			serverPublicKey1024 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
			serverPublicKey2048 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		}
	}
	
	/**
	 * Can generate random numbers with (to - from) < 256.
	 * 
	 * @param from (inclusive)
	 * @param to (inclusive)
	 * @return
	 */
	static short getRandomNumber(short from, short to) {		
		random.generateData(randomNumberWorkspace, Constants.ZERO, (short)randomNumberWorkspace.length);
		return (short) ((short) ((short) ((short)(randomNumberWorkspace[0] + 128) & 0xFF) % (short) (to + 1 - from)) + from);
	}

	static void generateRandom(ArrayPointer dest) {
		random.generateData(dest.data, dest.offset, dest.length);
	}

	static void generateRandom(byte [] destination, short destinationOffset, short length) {
		random.generateData(destination, destinationOffset, length);
	}
	
	/**
	 * Find the public key in a X.509 Certificate.
	 * 
	 * @param certificate
	 * @param offset of the key in the given array
	 * @return
	 */
	static short findPublicKeyOffset(byte [] certificate, short offset) {
		// certificate
		offset += ASN1Tools.jumpInto(certificate, offset);
		// signed certificate
		offset += ASN1Tools.jumpInto(certificate, offset);
		// version
		offset += ASN1Tools.jumpOver(certificate, offset);
		// serialnumber
		offset += ASN1Tools.jumpOver(certificate, offset);
		// signature
		offset += ASN1Tools.jumpOver(certificate, offset);
		// issuer
		offset += ASN1Tools.jumpOver(certificate, offset);
		// validity
		offset += ASN1Tools.jumpOver(certificate, offset);
		// subject
		offset += ASN1Tools.jumpOver(certificate, offset);
		// subjectpublickeyinfo
		offset += ASN1Tools.jumpInto(certificate, offset);
		// algorithm
		offset += ASN1Tools.jumpOver(certificate, offset);
		// subjectPublicKey
		offset += ASN1Tools.jumpInto(certificate, offset);
		return offset;
	}
	
	/**
	 * Parse a RSA public keys ASN1 structure to create an RSAPublicKey object with exponent and modulus.
	 * 
	 * @param publicKey
	 * @param offset
	 * @return
	 */
	
	static RSAPublicKey parse(byte [] publicKey, short offset){
		
		// jump over header
		ASN1Tools.getLengthOfStructure(publicKey, offset);
		offset += ASN1Tools.lastNumberOfIdentifierOctets + ASN1Tools.lastNumberOfLengthOctets;
		
		
		short modLength = (short) (ASN1Tools.getLengthOfStructure(publicKey, offset) - ASN1Tools.lastNumberOfIdentifierOctets - ASN1Tools.lastNumberOfLengthOctets);
		short modOffset = (short) (offset + ASN1Tools.lastNumberOfIdentifierOctets + ASN1Tools.lastNumberOfLengthOctets);
		offset += modLength + ASN1Tools.lastNumberOfIdentifierOctets + ASN1Tools.lastNumberOfLengthOctets;

		// sometimes keys have an additional 0x00 in front to prevent
		// misinterpretation as negative number, for use in javacard this needs to be stripped
		if (modLength % 8 == 1){
			modOffset++;
			modLength--;
		}
		
		short expLength = (short) (ASN1Tools.getLengthOfStructure(publicKey, offset) - ASN1Tools.lastNumberOfIdentifierOctets - ASN1Tools.lastNumberOfLengthOctets);
		short expOffset = (short) (offset + ASN1Tools.lastNumberOfIdentifierOctets + ASN1Tools.lastNumberOfLengthOctets);

		
		
		
		//TODO intelligent solution for key management
		RSAPublicKey key = getPublicKeyForSize((short) (modLength * 8));
		key.setModulus(publicKey, modOffset, modLength);
		key.setExponent(publicKey, expOffset, expLength);
		return key;
	}
	
	static RSAPublicKey getPublicKeyForSize(short size){
		switch(size){
			case KeyBuilder.LENGTH_RSA_512:
				return serverPublicKey512;
			case KeyBuilder.LENGTH_RSA_1024:
				return serverPublicKey1024;
			case KeyBuilder.LENGTH_RSA_2048:
				return serverPublicKey2048;
			default:
				return null;
		}
	}
}
