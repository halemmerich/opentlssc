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

import javacard.framework.Util;
import javacard.security.MessageDigest;


/**
 * Implements the TLS pseudo random function.
 * 
 * @author Martin Boonk
 *
 */
class Crypto_Prf {
	private Crypto_HMAC hmac = new Crypto_HMAC(MessageDigest.ALG_SHA_256);
	
	
	Crypto_Prf(){
	}
	
	/**
	 * Calculate the wantedLength of pseudo random bytes using the given seed, label and secret.
	 * The result is stored in the given destination.
	 * 
	 * @param dest
	 * @param destOff
	 * @param destLen
	 * @param secret
	 * @param secretOff
	 * @param secretLen
	 * @param label
	 * @param seed
	 * @param seedOff
	 * @param seedLen
	 * @param wantedLength
	 */
	void expand(byte [] dest, short destOff, short destLen
			, byte [] secret, short secretOff, short secretLen
			, byte [] label, short labelOff, short labelLen,
			byte [] seed, short seedOff, short seedLen, short wantedLength) {
		short hmacLength = hmac.getLength();
		short iterations = (short) (wantedLength / hmacLength);
		
		short rest = (short) (wantedLength % hmacLength);
		if (rest > 0){
			iterations++;
		}


		short destinationPointer = destOff;
		byte [] tempSpace = TransientTools.getWorkspace(this, false);
		for (short i = 0; i < iterations; i++){
			if (i == 0){
				// if first run of loop, create A(1), A(0) being the seed
				hmac.init(secret, secretOff, secretLen);
				hmac.update(label, labelOff, labelLen);
				hmac.doFinal(seed, seedOff, seedLen, tempSpace, Constants.ZERO);
			} else {
				// else create A(i-1)
				hmac.init(secret, secretOff, secretLen);
				hmac.doFinal(tempSpace, Constants.ZERO, hmac.getLength(), tempSpace, Constants.ZERO);
			}
			
			
			if (i < (short)(iterations - 1) || (i == (short)(iterations - 1) && rest == 0)) {
				// create the pseudo random bytes by calculating HMAC(secret, A(i) + seed) and store in destination
				hmac.init(secret, secretOff, secretLen);
				hmac.update(tempSpace, Constants.ZERO, hmac.getLength());
				hmac.update(label, labelOff, labelLen);
				hmac.doFinal(seed, seedOff, seedLen, dest, destinationPointer);
				destinationPointer += hmac.getLength();
			}
			if (i == (short)(iterations - 1) && rest > 0) {
				// create the pseudo random bytes by calculating HMAC(secret, A(i) + seed)
				// and store in workspace to copy only the needed bytes into destination
				hmac.init(secret, secretOff, secretLen);
				hmac.update(tempSpace, Constants.ZERO, hmac.getLength());
				hmac.update(label,labelOff, labelLen);
				hmac.doFinal(seed, seedOff, seedLen, tempSpace, Constants.ZERO);
				Util.arrayCopyNonAtomic(tempSpace, Constants.ZERO, dest, destinationPointer, rest);
			}
		}
		TransientTools.freeWorkspace(tempSpace);
	
	}
	
	void expand(byte [] dest, short destOff, short destLen, byte [] secret, short secretOff, short secretLen, ArrayPointer label,byte [] seed, short seedOff, short seedLen, short wantedLength){
		expand(dest, destOff, destLen, secret, secretOff, secretLen, label.data, label.offset, label.length, seed, seedOff, seedLen, wantedLength);
	}

	void expand(ArrayPointer dest, ArrayPointer secret, ArrayPointer label, ArrayPointer seed, short wantedLength) {
		expand(dest.data, dest.offset, dest.length, secret.data, secret.offset, secret.length, label, seed.data, seed.offset, seed.length, wantedLength);
	}
	
	void expand(ArrayPointer dest, ArrayPointer secret, ArrayPointer label, byte[] seed, short seedOff, short seedLen, short wantedLength) {
		expand(dest.data, dest.offset, dest.length, secret.data, secret.offset, secret.length, label, seed, seedOff, seedLen, wantedLength);
	}

	void expand(ArrayPointer dest, byte[] secret, short secretOffset, short secretLength, ArrayPointer label, ArrayPointer seed, short wantedLength) {
		expand(dest.data, dest.offset, dest.length, secret, secretOffset, secretLength, label, seed.data, seed.offset, seed.length, wantedLength);
	}

	void expand(ArrayPointer dest, byte[] secret, short secretOffset, short secretLength, ArrayPointer label, byte [] seed, short seedOffset, short seedLength, short wantedLength) {
		expand(dest.data, dest.offset, dest.length, secret, secretOffset, secretLength, label, seed, seedOffset, seedLength, wantedLength);
	}

}
