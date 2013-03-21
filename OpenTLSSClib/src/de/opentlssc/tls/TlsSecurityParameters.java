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
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;

class TlsSecurityParameters {
	ArrayPointer	keyBlock;
	ArrayPointer	clientMacWriteKey;
	ArrayPointer	serverMacWriteKey;
	ArrayPointer	clientWriteKey;
	ArrayPointer	serverWriteKey;

	ArrayPointer	clientRandomBytes;
	ArrayPointer	serverRandomBytes;
	ArrayPointer	masterSecret;

	PrimitiveShort	clientSequenceNumber;
	PrimitiveShort	serverSequenceNumber;

	private byte[]	data;

	short			cipherSuite				= 0;
	static boolean	abbreviatedHandshake	= false;

	short			alert;

	TlsSecurityParameters() {
		short offset = 0;
		if (LibraryConfiguration.CONFIG_STORE_CONNECTION_STATES_IN_RAM) {
			data = JCSystem.makeTransientByteArray((short) (LibraryConfiguration.CONFIG_KEYBLOCK_MAX_SIZE
					+ Constants.LENGTH_RANDOM_BYTES + Constants.LENGTH_RANDOM_BYTES + Constants.LENGTH_MASTER_SECRET),
					JCSystem.CLEAR_ON_DESELECT);
		} else {
			data = new byte[LibraryConfiguration.CONFIG_KEYBLOCK_MAX_SIZE + Constants.LENGTH_RANDOM_BYTES
					+ Constants.LENGTH_RANDOM_BYTES + Constants.LENGTH_MASTER_SECRET];
		}
		clientRandomBytes = new ArrayPointer(data, offset, Constants.LENGTH_RANDOM_BYTES);
		offset += Constants.LENGTH_RANDOM_BYTES;
		serverRandomBytes = new ArrayPointer(data, offset, Constants.LENGTH_RANDOM_BYTES);
		offset += Constants.LENGTH_RANDOM_BYTES;
		masterSecret = new ArrayPointer(data, offset, Constants.LENGTH_MASTER_SECRET);
		offset += Constants.LENGTH_MASTER_SECRET;

		keyBlock = new ArrayPointer(data, offset, LibraryConfiguration.CONFIG_KEYBLOCK_MAX_SIZE);
		clientSequenceNumber = new PrimitiveShort((short) 0, (short) 8);
		serverSequenceNumber = new PrimitiveShort((short) 0, (short) 8);
		clientMacWriteKey = new ArrayPointer(keyBlock.data, keyBlock.offset, Constants.ZERO);
		serverMacWriteKey = new ArrayPointer(keyBlock.data, keyBlock.offset, Constants.ZERO);
		clientWriteKey = new ArrayPointer(keyBlock.data, keyBlock.offset, Constants.ZERO);
		serverWriteKey = new ArrayPointer(keyBlock.data, keyBlock.offset, Constants.ZERO);
	}

	void reset() {
		alert = Util.makeShort(Constants.TLS_ALERT_LEVEL_FATAL, Constants.TLS_ALERT_REASON_INTERNAL_ERROR);
		cipherSuite = Constants.TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL;
		keyBlock.length = 0;
		clientMacWriteKey.length = 0;
		serverMacWriteKey.length = 0;
		clientWriteKey.length = 0;
		serverWriteKey.length = 0;

		clientSequenceNumber.value = 0;
		serverSequenceNumber.value = 0;
	}

	/**
	 * set ciphersuite first
	 */
	void rebuild() {
		switch (cipherSuite) {
		case Constants.TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL:
			clientMacWriteKey.length = 0;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_MD5:
			clientMacWriteKey.length = MessageDigest.LENGTH_MD5;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
			clientMacWriteKey.length = MessageDigest.LENGTH_SHA;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA256:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
			clientMacWriteKey.length = MessageDigest.LENGTH_SHA_256;
			break;
		}

		switch (cipherSuite) {
		case Constants.TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_MD5:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA256:
			clientWriteKey.length = 0;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
			clientWriteKey.length = (short) (KeyBuilder.LENGTH_AES_128 / 8);
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
			clientWriteKey.length = (short) (KeyBuilder.LENGTH_AES_192 / 8);
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
			clientWriteKey.length = (short) (KeyBuilder.LENGTH_DES3_3KEY / 8);
			break;
		}

		serverMacWriteKey.length = clientMacWriteKey.length;
		serverWriteKey.length = clientWriteKey.length;

		clientMacWriteKey.offset = keyBlock.offset;
		serverMacWriteKey.offset = (short) (clientMacWriteKey.offset + clientMacWriteKey.length);
		clientWriteKey.offset = (short) (serverMacWriteKey.offset + serverMacWriteKey.length);
		serverWriteKey.offset = (short) (clientWriteKey.offset + clientWriteKey.length);

		keyBlock.length = (short) (clientMacWriteKey.length + serverMacWriteKey.length + clientWriteKey.length + serverWriteKey.length);
	}
}
