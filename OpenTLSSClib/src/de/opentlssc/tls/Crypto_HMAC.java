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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * This class implements an HMAC.
 * 
 * @author Martin Boonk
 *
 */
class Crypto_HMAC{
	private final short				LENGTH_HMAC_HASH_BLOCKSIZE;

	static final byte	HMAC_OUTER_PADDING_VALUE	= (byte) 0x5C;
	static final byte	HMAC_INNER_PADDING_VALUE	= (byte) 0x36;
	
	final MessageDigest digest;

	byte [] outgoingSecret;
	byte [] finalWorkspace;
	
	/**
	 * Create an instance of the HMAC using the specified algorithm.
	 * 
	 * @param algorithm type (found as constants in MessageDigest)
	 */
	Crypto_HMAC(byte algorithm) {
		digest = MessageDigest.getInstance(algorithm, false);
		switch (algorithm){
		case MessageDigest.ALG_MD5:
		case MessageDigest.ALG_SHA:
		case MessageDigest.ALG_SHA_256:
			LENGTH_HMAC_HASH_BLOCKSIZE = 64;
			break;
		default:
			LENGTH_HMAC_HASH_BLOCKSIZE = 64;
		}
		if (LibraryConfiguration.CONFIG_TRANSIENT_HMAC){
			outgoingSecret = JCSystem.makeTransientByteArray(LENGTH_HMAC_HASH_BLOCKSIZE, JCSystem.CLEAR_ON_DESELECT);
			finalWorkspace = JCSystem.makeTransientByteArray(digest.getLength(), JCSystem.CLEAR_ON_DESELECT);
		} else {
			outgoingSecret = new byte [LENGTH_HMAC_HASH_BLOCKSIZE];
			finalWorkspace = new byte [digest.getLength()];
		}
	}

	/**
	 * Initialize the HMAC with the secret.
	 * 
	 * @param secret
	 * @param secretOff
	 * @param secretLen
	 */
	void init(byte [] secret, short secretOff, short secretLen){
		digest.reset();
		prepareKey(secret, secretOff, secretLen, outgoingSecret, Constants.ZERO, HMAC_INNER_PADDING_VALUE);
		digest.update(outgoingSecret, (short) 0, (short) LENGTH_HMAC_HASH_BLOCKSIZE);
		prepareKey(secret, secretOff, secretLen, outgoingSecret, Constants.ZERO, HMAC_OUTER_PADDING_VALUE);
	}
	
	void init(ArrayPointer secret) {
		init(secret.data, secret.offset, secret.length);
	}

	/**
	 * Prepares the HMAC padding by XORing it with a value and doing a hash of the key if it is bigger than the blocksize.
	 * 
	 * @param xorValue
	 */
	private void prepareKey(byte [] secret, short secretOff, short secretLen, byte [] dest, short offset, byte xorValue){
		short keylength = 0;
		if (secretLen > LENGTH_HMAC_HASH_BLOCKSIZE){
			keylength = digest.doFinal(secret, secretOff, (short) secretLen, dest, offset);
			Util.arrayFillNonAtomic(dest, digest.getLength(), (short) (LENGTH_HMAC_HASH_BLOCKSIZE - digest.getLength()),xorValue);
		} else {
			Util.arrayCopyNonAtomic(secret, secretOff, dest, offset, secretLen);
			keylength = (short) secretLen;
			Util.arrayFillNonAtomic(dest, (short) secretLen,(short) (LENGTH_HMAC_HASH_BLOCKSIZE - secretLen),xorValue);
		}
		
		for (short i = offset; i < (short)(keylength + offset); i++){
			dest[i] ^= xorValue;
		}
	}
	
	void update(ArrayPointer data) {
		update(data.data, data.offset, data.length);
	}

	short doFinal(ArrayPointer data, ArrayPointer out) {
		return doFinal(data.data, data.offset, data.length, out.data, out.offset);
	}

	/**
	 * Finalize the HMAC and output the result.
	 * 
	 * @param dest
	 * @param offset
	 * @return
	 */
	short doFinal(byte [] dest, short offset) {
		return doFinal(dest, Constants.ZERO, Constants.ZERO, dest, offset);
	}

	/**
	 * Update, finalize the HMAC and output the result.
	 * 
	 * @param dest
	 * @param offset
	 * @return
	 */	
	short doFinal(byte [] data, short inOffset, short length, byte [] dest, short offset){
		digest.doFinal(data, inOffset, length, finalWorkspace, Constants.ZERO);
		digest.update(outgoingSecret, (short) 0 , LENGTH_HMAC_HASH_BLOCKSIZE);
		digest.doFinal(finalWorkspace, Constants.ZERO, getLength(), dest, offset);
		return digest.getLength();
	}
	
	/**
	 * Get the length in bytes of the used digest.
	 * 
	 * @return length
	 */
	short getLength(){
		return digest.getLength();
	}

	/**
	 * Update the HMACs content.
	 * 
	 * @param data
	 * @param offset
	 * @param length
	 */
	void update(byte[] data, short offset, short length) {
		digest.update(data, offset, length);
	}
}
