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

import javacard.framework.CardRuntimeException;
import javacard.framework.Util;

class RecordTools{
	
	TLS tls;
	
	public RecordTools(TLS tls) {
		this.tls = tls;
	}

	void parseAlert(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
	}

	void parseFinished(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
		tls.getTlsTools().handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
		checkFinishedValue(buffer, offset);
	}

	private void checkFinishedValue(byte[] buffer, short offset) {
		ArrayPointer currentVerifyData = tls.getTlsTools().getCurrentClientSecurityParameters().verifyData;
		if (0 != Util.arrayCompare(buffer, Constants.OFFSET_TLS_FINISHED_IN_RECORD, currentVerifyData.data, currentVerifyData.offset, currentVerifyData.length)){
			tls.getTlsTools().getCurrentClientSecurityParameters().alert = Utilities.buildAlert(true, Constants.TLS_ALERT_REASON_DECODE_ERROR);
			CardRuntimeException.throwIt((short) 0);
		}
	}

	void parseServerHelloDone(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
		tls.getTlsTools().handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
	}

	void parseChangeCipherSpec(byte[] buffer, short offset, short length) {
		if (buffer[offset + Constants.LENGTH_TLS_RECORD_HEADER] != 1){
			tls.getTlsTools().getCurrentClientSecurityParameters().alert = Utilities.buildAlert(true, Constants.TLS_ALERT_REASON_UNEXPECTED_MESSAGE);
			CardRuntimeException.throwIt((short) 0);
		}
		tls.getTlsTools().handshakeHashFinishServer(tls.getTlsTools().getCurrentClientSecurityParameters());
	}
	
	void parseServerHello(byte[] buffer, short offset, short length){
		checkHandshake(buffer, offset, length);
		tls.getTlsTools().handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));
		offset += Constants.LENGTH_TLS_RECORD_HEADER + Constants.LENGTH_TLS_HANDSHAKE_HEADER + 2;
		ArrayPointer nextServerRandomBytes = tls.getTlsTools().getNextClientSecurityParameters().serverRandomBytes;
		Util.arrayCopyNonAtomic(buffer, offset, nextServerRandomBytes.data, nextServerRandomBytes.offset, nextServerRandomBytes.length);
		offset += Constants.LENGTH_RANDOM_BYTES;
		
		short serverSessionIdLength = (short) (buffer[offset] & 0xFF);
		offset += Constants.LENGTH_SESSIONID_LENGTH;
		ArrayPointer nextSessionId = tls.getTlsTools().getNextClientSecurityParameters().sessionId; 
		Util.arrayCopyNonAtomic(buffer, offset, nextSessionId.data, nextSessionId.offset, serverSessionIdLength);
		nextSessionId.length = serverSessionIdLength;

		
		offset += serverSessionIdLength;
		tls.getTlsTools().getNextClientSecurityParameters().cipherSuite = Util.getShort(buffer, offset);
	}

	void parseCertificate(byte[] buffer, short offset, short length) {
		checkHandshake(buffer, offset, length);
		tls.getTlsTools().handshakeHashUpdate(buffer, (short) (offset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length - Constants.LENGTH_TLS_RECORD_HEADER));

		tls.getTlsTools().createPublicKeyFromCertificate(buffer, (short) (offset + Constants.OFFSET_TLS_CERTIFICATE_DATA_IN_RECORD));
	}
	
	static void parseApplicationData(byte [] recordData, short recordDataOffset, short recordDataLength, byte [] destination, short destinationOffset){
		Util.arrayCopyNonAtomic(recordData, (short) (recordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER), destination, destinationOffset, (short) (recordDataLength + Constants.LENGTH_TLS_RECORD_HEADER));
	}
	
	static short writeAlert(byte [] recordData, short recordDataOffset, short alert) {
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_ALERT_VALUE, recordData, recordDataOffset);
		recordDataOffset = Util.setShort(recordData, recordDataOffset, Utilities.buildAlert(false, Constants.TLS_ALERT_REASON_CLOSE_NOTIFY));
		writeRecordHeaderLength((short) 2, recordData, recordDataOffset);
		return recordDataOffset;
	}

	short writeClientHello(byte [] recordData, short recordDataOffset){
		tls.getTlsTools().generateClientRandomBytes();
		short initialOffset = recordDataOffset;
		
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = writeHandshakeHeader(Constants.TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_HELLO, recordData, recordDataOffset);

		ArrayPointer sessionId;
		ArrayPointer clientRandomBytes = tls.getTlsTools().getNextClientSecurityParameters().clientRandomBytes;
		sessionId = tls.getTlsTools().getCurrentClientSecurityParameters().sessionId;
		
		
		short recordContentOffset = recordDataOffset; 
		recordDataOffset = Util.setShort(recordData, recordDataOffset, Constants.TLS_VERSION);
		recordDataOffset = Util.arrayCopyNonAtomic(clientRandomBytes.data, clientRandomBytes.offset, recordData, recordDataOffset, clientRandomBytes.length);
		recordData[recordDataOffset ++] = (byte) sessionId.length;
		recordDataOffset = Util.arrayCopyNonAtomic(sessionId.data, sessionId.offset, recordData, recordDataOffset, sessionId.length);
		
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
		
		recordData[recordDataOffset ++] = Constants.LENGTH_COMPRESSION_METHODS_LENGTH;
		recordData[recordDataOffset ++] = Constants.TLS_COMPRESSION_METHOD_NULL;
				
		short length = (short) (recordDataOffset - recordContentOffset);
		
		writeRecordHeaderLength((short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER), recordData, initialOffset);
		writeHandshakeHeaderLength(length, recordData, initialOffset);
		
		tls.getTlsTools().handshakeHashUpdate(recordData, (short) (initialOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER));
		return recordDataOffset;
	}
	
	short writeClientKeyExchange(byte [] recordData, short recordDataOffset){
		short initialOffset = recordDataOffset;
		
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = writeHandshakeHeader(Constants.TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_KEY_EXCHANGE, recordData, recordDataOffset);

		short length = tls.getTlsTools().encryptPreMasterSecret(recordData, (short) (recordDataOffset + Constants.LENGTH_ENCRYPTED_PRE_MASTER_SECRET_LENGTH));
		Util.setShort(recordData, recordDataOffset, length);
		length += Constants.LENGTH_ENCRYPTED_PRE_MASTER_SECRET_LENGTH;
		recordDataOffset += length;
		writeRecordHeaderLength((short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER), recordData, initialOffset);
		writeHandshakeHeaderLength(length, recordData, initialOffset);
		
		tls.getTlsTools().handshakeHashUpdate(recordData, (short) (initialOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (length + Constants.LENGTH_TLS_HANDSHAKE_HEADER));
		return recordDataOffset;
	}

	short writeChangeCipherSpec(byte [] recordData, short recordDataOffset) {
		short initialOffset = recordDataOffset;
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC_VALUE, recordData, recordDataOffset);
		recordData[recordDataOffset] = 0x01;
		writeRecordHeaderLength((short) (1), recordData, initialOffset);
		
		tls.getTlsTools().handshakeHashFinishClient(tls.getTlsTools().getNextClientSecurityParameters());
		return (short) (recordDataOffset + 1);
	}

	short writeFinished(byte [] recordData, short recordDataOffset) {
		short initialOffset = recordDataOffset;
		recordDataOffset = writeRecordHeader(Constants.TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE, recordData, recordDataOffset);
		recordDataOffset = writeHandshakeHeader(Constants.TLS_HANDSHAKE_CONTENT_TYPE_FINISHED, recordData, recordDataOffset);
		ArrayPointer verifyData = tls.getTlsTools().getCurrentClientSecurityParameters().verifyData;
		recordDataOffset = Util.arrayCopyNonAtomic(verifyData.data, verifyData.offset, recordData, recordDataOffset, verifyData.length);
		writeRecordHeaderLength((short) (verifyData.length + Constants.LENGTH_TLS_HANDSHAKE_HEADER), recordData, initialOffset);
		writeHandshakeHeaderLength(verifyData.length, recordData, initialOffset);
		tls.getTlsTools().handshakeHashUpdate(recordData, (short) (initialOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (verifyData.length + Constants.LENGTH_TLS_HANDSHAKE_HEADER));
		return recordDataOffset;
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
		Util.setShort(recordData, recordDataOffset, recordContentLength);
	}

	static short writeHandshakeHeader(byte handshakeType, byte [] recordData, short recordDataOffset){
		recordData[recordDataOffset++] = handshakeType;
		recordData[recordDataOffset++] = 0;
		return (short) (recordDataOffset + 2);
	}
	
	static void writeHandshakeHeaderLength(short handshakeContentLength, byte [] recordData, short recordDataOffset){
		recordDataOffset += Constants.LENGTH_TLS_RECORD_HEADER + Constants.OFFSET_TLS_HANDSHAKE_LENGTH_IN_RECORD_CONTENT + 1;
		Util.setShort(recordData, recordDataOffset, handshakeContentLength);
	}

	void checkRecord(byte [] recordData, short recordDataOffset, short recordDataLength){
		if (Util.getShort(recordData, (short) (recordDataOffset + Constants.OFFSET_TLS_RECORD_LENGTH)) != recordDataLength - Constants.LENGTH_TLS_RECORD_HEADER){
			tls.getTlsTools().getCurrentClientSecurityParameters().alert = Utilities.buildAlert(true, Constants.TLS_ALERT_REASON_RECORD_OVERFLOW);
			CardRuntimeException.throwIt((short) 0);
		}
	}

	void checkHandshake(byte [] recordData, short recordDataOffset, short recordDataLength){
		if (Util.getShort(recordData, (short) (recordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER + Constants.OFFSET_TLS_HANDSHAKE_LENGTH_IN_RECORD_CONTENT + 1)) != recordDataLength - Constants.LENGTH_TLS_RECORD_HEADER - Constants.LENGTH_TLS_HANDSHAKE_HEADER){
			tls.getTlsTools().getCurrentClientSecurityParameters().alert = Utilities.buildAlert(true, Constants.TLS_ALERT_REASON_UNEXPECTED_MESSAGE);
			CardRuntimeException.throwIt((short) 0);
		}
	}
}
