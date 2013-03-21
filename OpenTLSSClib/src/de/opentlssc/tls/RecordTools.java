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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

class RecordTools{

	static void parseAlert(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
	}

	static void parseFinished(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
		TlsTools.handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
		checkFinishedValue(buffer, offset);
	}

	private static void checkFinishedValue(byte[] buffer, short offset) {
		if (0 != Util.arrayCompare(buffer, Constants.OFFSET_TLS_FINISHED_IN_RECORD, Data.verifyData.data, Data.verifyData.offset, Data.verifyData.length)){
		//	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	static void parseServerHelloDone(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
		TlsTools.handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
	}

	static void parseChangeCipherSpec(byte[] buffer, short offset, short length) {
		if (buffer[offset + Constants.LENGTH_TLS_RECORD_HEADER] != 1){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}
	
	static void parseServerHello(byte[] buffer, short offset, short length){
		checkHandshake(buffer, offset, length);
		TlsTools.handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
		offset += Constants.LENGTH_TLS_RECORD_HEADER + Constants.LENGTH_TLS_HANDSHAKE_HEADER + 2;
		TlsTools.getNextClientSecurityParameters().serverRandomBytes.set(buffer, offset);
		offset += Constants.LENGTH_RANDOM_BYTES;
		
		short serverSessionIdLength = (short) (buffer[offset] & 0xFF);
		offset += Constants.LENGTH_SESSIONID_LENGTH;
		if (Data.sessionId.length == serverSessionIdLength && 0 == Util.arrayCompare(Data.sessionId.data, Data.sessionId.offset, buffer, offset, Data.sessionId.length)){
			TlsSecurityParameters.abbreviatedHandshake = true;
		} else {
			Data.sessionId.length = serverSessionIdLength;	
			Data.sessionId.set(buffer, offset);
		}
		offset += Data.sessionId.length;
		TlsTools.getNextClientSecurityParameters().cipherSuite = Util.getShort(buffer, offset);
	}

	static void parseCertificate(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
		TlsTools.handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
		
		// get length of first certificate
		Data.serverCertificate.length = Util.getShort(buffer, (short) (offset
				+ Constants.OFFSET_TLS_CERTIFICATE_LENGTH_IN_RECORD + 1));
		offset += Constants.OFFSET_TLS_CERTIFICATE_DATA_IN_RECORD;
		length -= Constants.OFFSET_TLS_CERTIFICATE_DATA_IN_RECORD;
		TlsTools.createPublicKeyFromCertificate(buffer, offset);
	}
	
	static void parseApplicationData(byte [] recordData, short recordDataOffset, short recordDataLength, byte [] destination, short destinationOffset){
		Util.arrayCopyNonAtomic(recordData, (short) (recordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER), destination, destinationOffset, (short) (recordDataLength + Constants.LENGTH_TLS_RECORD_HEADER));
	}
	
	static short writeAlert(byte [] recordData, short recordDataOffset) {
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = Util.setShort(recordData, recordDataOffset, TlsTools.getCurrentClientSecurityParameters().alert);
		writeRecordHeaderLength((short) 2, recordData, recordDataOffset);
		return recordDataOffset;
	}

	static short writeClientHello(byte [] recordData, short recordDataOffset){
		TlsTools.generateClientRandomBytes();
		short initialOffset = recordDataOffset;
		
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = writeHandshakeHeader(Constants.TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_HELLO, recordData, recordDataOffset);
		
		short recordContentOffset = recordDataOffset; 
		recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_VERSION);
		recordDataOffset += TlsTools.getNextClientSecurityParameters().clientRandomBytes.copy(recordData, recordDataOffset);
		recordData[recordDataOffset ++] = (byte) Data.sessionId.length;
		recordDataOffset += Data.sessionId.copy(recordData, recordDataOffset);
		
		// construct cipher suite array
		// create the ciphersuites according to applet configuration
		short offsetCipherSuitesLength = recordDataOffset;
		recordDataOffset += 2;
		
		if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_AES_256){
			if (LibraryConfiguration.CONFIG_SHA_256){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256);
			}
			if (LibraryConfiguration.CONFIG_SHA){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA);
			}
		}		
		if (LibraryConfiguration.CONFIG_AES_128){
			if (LibraryConfiguration.CONFIG_SHA_256){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256);
			}
			if (LibraryConfiguration.CONFIG_SHA){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA);
			}
		}
		if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_3DES && LibraryConfiguration.CONFIG_SHA){
			recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA);
			
		}
		if (LibraryConfiguration.CONFIG_NULL_CIPHER){
			if (LibraryConfiguration.CONFIG_SHA_256){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA256);
			}
			if (LibraryConfiguration.CONFIG_SHA){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA);
			}
			if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_MD5){
				recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_MD5);
			}
		}
		Utilities.setShort(recordData, offsetCipherSuitesLength, Constants.LENGTH_CIPHER_SUITES_LENGTH, (short) (recordDataOffset - 2 - offsetCipherSuitesLength));
		
		recordData[recordDataOffset ++] = (byte) Data.compressionMethods.length;
		recordDataOffset += Data.compressionMethods.copy(recordData, recordDataOffset);
		
		if (Data.extensions.length > 0) {
			recordDataOffset = Utilities.writeLengthField(recordData, recordDataOffset, Constants.LENGTH_EXTENSIONS_LENGTH, Data.extensions.length);
		}
		
		short length = (short) (recordDataOffset - recordContentOffset);
		
		writeRecordHeaderLength((short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER), recordData, initialOffset);
		writeHandshakeHeaderLength(length, recordData, initialOffset);
		
		TlsTools.handshakeHashUpdate(recordData, (short) (initialOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER));
		return recordDataOffset;
	}
	
	static short writeClientKeyExchange(byte [] recordData, short recordDataOffset){
		short initialOffset = recordDataOffset;
		
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = writeHandshakeHeader(Constants.TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_KEY_EXCHANGE, recordData, recordDataOffset);

		short length = TlsTools.encryptPreMasterSecret(recordData, (short) (recordDataOffset + Constants.LENGTH_ENCRYPTED_PRE_MASTER_SECRET_LENGTH));
		Util.setShort(recordData, recordDataOffset, length);
		length += Constants.LENGTH_ENCRYPTED_PRE_MASTER_SECRET_LENGTH;
		recordDataOffset += length;
		writeRecordHeaderLength((short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER), recordData, initialOffset);
		writeHandshakeHeaderLength(length, recordData, initialOffset);
		
		TlsTools.handshakeHashUpdate(recordData, (short) (initialOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER));
		return recordDataOffset;
	}

	static short writeChangeCipherSpec(byte [] recordData, short recordDataOffset) {
		short initialOffset = recordDataOffset;
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC_VALUE, recordData, recordDataOffset);
		recordData[recordDataOffset] = 0x01;
		writeRecordHeaderLength((short) (1), recordData, initialOffset);
		
		TlsTools.handshakeHashFinishClient(TlsTools.getNextClientSecurityParameters());
		return (short) (recordDataOffset + 1);
	}

	static short writeFinished(byte [] recordData, short recordDataOffset) {
		short initialOffset = recordDataOffset;
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = writeHandshakeHeader(Constants.TLS_HANDSHAKE_CONTENT_TYPE_FINISHED, recordData, recordDataOffset);
		short length = Data.verifyData.copy(recordData, recordDataOffset);
		writeRecordHeaderLength((short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER), recordData, initialOffset);
		writeHandshakeHeaderLength(length, recordData, initialOffset);
		TlsTools.handshakeHashUpdate(recordData, (short) (initialOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER));
		return (short) (recordDataOffset + length);
	}
	
	static short writeApplicationData(byte [] dataToSend, short dataToSendOffset, short dataToSendLength, byte [] recordData, short recordDataOffset) {
		short initialOffset = recordDataOffset;
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA_VALUE, recordData, recordDataOffset);
		recordDataOffset = Util.arrayCopyNonAtomic(dataToSend, dataToSendOffset, recordData, recordDataOffset, dataToSendLength);
		writeRecordHeaderLength(dataToSendLength, recordData, initialOffset);
		return recordDataOffset;
	}

	static short writeRecordHeader(byte recordType, byte [] recordData, short recordDataOffset){
		recordData[recordDataOffset++] = recordType;
		recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_VERSION);
		return (short) (recordDataOffset + 2);
	}
	
	static void writeRecordHeaderLength(short recordContentLength, byte [] recordData, short recordDataOffset){
		recordDataOffset += Constants.OFFSET_TLS_RECORD_LENGTH;
		recordDataOffset = Util.setShort(recordData, recordDataOffset, recordContentLength);
	}

	static short writeHandshakeHeader(byte handshakeType, byte [] recordData, short recordDataOffset){
		recordData[recordDataOffset++] = handshakeType;
		recordData[recordDataOffset++] = 0;
		return (short) (recordDataOffset + 2);
	}
	
	static void writeHandshakeHeaderLength(short handshakeContentLength, byte [] recordData, short recordDataOffset){
		recordDataOffset += Constants.LENGTH_TLS_RECORD_HEADER + Constants.OFFSET_TLS_HANDSHAKE_LENGTH_IN_RECORD_CONTENT + 1;
		recordDataOffset = Util.setShort(recordData, recordDataOffset, handshakeContentLength);
	}

	static void checkRecord(byte [] recordData, short recordDataOffset, short recordDataLength){
		if (Util.getShort(recordData, (short) (recordDataOffset + Constants.OFFSET_TLS_RECORD_LENGTH)) != recordDataLength - Constants.LENGTH_TLS_RECORD_HEADER){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	static void checkHandshake(byte [] recordData, short recordDataOffset, short recordDataLength){
		if (Util.getShort(recordData, (short) (recordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER + Constants.OFFSET_TLS_HANDSHAKE_LENGTH_IN_RECORD_CONTENT + 1)) != recordDataLength - Constants.LENGTH_TLS_RECORD_HEADER - Constants.LENGTH_TLS_HANDSHAKE_HEADER){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}
}
