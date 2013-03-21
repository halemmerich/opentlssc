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
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

public class TLS {
	private byte handshakeState = 0;
	private byte transmissionState;
	private byte tlsState;
	
	public TLS(){

		try {
			MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
		} catch (Exception e){
			LibraryConfiguration.emu = true;
		}
		Constants.init();
		Data.init();
		CryptoTools.init();
		TlsTools.init();
		TransientTools.init();
		ASN1Tools.init();
	}
	
	public void initializeTls(){
		handshakeState = Constants.STATE_HANDSHAKE_HELLO;
		transmissionState = Constants.STATE_TRANSMISSION_SEND;
		tlsState = Constants.STATE_APPLET_HANDSHAKE;
	}

	public boolean anotherHandshakeMessageNeeded(){
		return checkIfAnotherMessageIsNeeded();
	}

	public short doHandshake(byte [] incomingRecordData, short incomingRecordDataOffset, short incomingRecordDataLength, byte [] outgoingRecordData, short outgoingRecordDataOffset){
		short initalOutgoingOffset = outgoingRecordDataOffset;
		if (incomingRecordDataLength > 0 && transmissionState == Constants.STATE_TRANSMISSION_RECEIVE && tlsState == Constants.STATE_APPLET_HANDSHAKE){
			RecordTools.checkRecord(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
			TlsTools.activateCurrentServerSecurityParameters();
			switch (handshakeState) {
			case Constants.STATE_HANDSHAKE_HELLO:
				incomingRecordDataLength = unwrapRecordData(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				RecordTools.parseServerHello(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);

				if (TlsSecurityParameters.abbreviatedHandshake){
					handshakeState = Constants.STATE_HANDSHAKE_CHANGE_CIPHER_SPEC;
					TlsTools.copyMasterSecretToNextSecurityParameters();
					TlsTools.generateKeyBlock(TlsTools.getNextClientSecurityParameters());
				} else {
					handshakeState = Constants.STATE_HANDSHAKE_CERTIFICATE;
				}
				
				break;
			case Constants.STATE_HANDSHAKE_CERTIFICATE:
				incomingRecordDataLength = unwrapRecordData(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				RecordTools.parseCertificate(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				handshakeState = Constants.STATE_HANDSHAKE_HELLO_DONE;
				break;
			case Constants.STATE_HANDSHAKE_HELLO_DONE:
				incomingRecordDataLength = unwrapRecordData(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				RecordTools.parseServerHelloDone(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				handshakeState = Constants.STATE_HANDSHAKE_KEY_EXCHANGE;
				transmissionState = Constants.STATE_TRANSMISSION_SEND;
				break;
			case Constants.STATE_HANDSHAKE_CHANGE_CIPHER_SPEC:
				TlsTools.serverHashActive = false;
				incomingRecordDataLength = unwrapRecordData(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				RecordTools.parseChangeCipherSpec(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				TlsTools.makeNextSecurityParametersCurrentForServer();
				handshakeState = Constants.STATE_HANDSHAKE_FINISHED;
				break;
			case Constants.STATE_HANDSHAKE_FINISHED:
				incomingRecordDataLength = unwrapRecordData(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				RecordTools.parseFinished(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
				if (TlsSecurityParameters.abbreviatedHandshake){
					handshakeState = Constants.STATE_HANDSHAKE_CHANGE_CIPHER_SPEC;
					transmissionState = Constants.STATE_TRANSMISSION_SEND;
				} else {
					handshakeState = Constants.STATE_HANDSHAKE_HELLO;
					transmissionState = Constants.STATE_TRANSMISSION_SEND;
					tlsState = Constants.STATE_APPLET_APPLICATION_DATA;	
				}
				break;
			}		
		}
		if (transmissionState == Constants.STATE_TRANSMISSION_SEND && tlsState == Constants.STATE_APPLET_HANDSHAKE){
			TlsTools.activateCurrentClientSecurityParameters();
			switch (handshakeState) {
			case Constants.STATE_HANDSHAKE_HELLO:
				TlsSecurityParameters.abbreviatedHandshake = false;
				TlsTools.handshakeHashInit();
				transmissionState = Constants.STATE_TRANSMISSION_RECEIVE;
				outgoingRecordDataOffset = RecordTools.writeClientHello(outgoingRecordData, outgoingRecordDataOffset);
				return wrapRecordData(outgoingRecordData, initalOutgoingOffset, (short) (outgoingRecordDataOffset - initalOutgoingOffset));
			case Constants.STATE_HANDSHAKE_KEY_EXCHANGE:
				handshakeState = Constants.STATE_HANDSHAKE_CHANGE_CIPHER_SPEC;
				outgoingRecordDataOffset = RecordTools.writeClientKeyExchange(outgoingRecordData, outgoingRecordDataOffset);
				TlsTools.generateKeyBlock(TlsTools.getNextClientSecurityParameters());
				return wrapRecordData(outgoingRecordData, initalOutgoingOffset, (short) (outgoingRecordDataOffset - initalOutgoingOffset));
			case Constants.STATE_HANDSHAKE_CHANGE_CIPHER_SPEC:
				TlsTools.clientHashActive = false;
				handshakeState = Constants.STATE_HANDSHAKE_FINISHED;
				outgoingRecordDataOffset = RecordTools.writeChangeCipherSpec(outgoingRecordData, outgoingRecordDataOffset);
				short offset = wrapRecordData(outgoingRecordData, initalOutgoingOffset, (short) (outgoingRecordDataOffset - initalOutgoingOffset));
				TlsTools.makeNextSecurityParametersCurrentForClient();
				return offset;
			case Constants.STATE_HANDSHAKE_FINISHED:
				if (TlsSecurityParameters.abbreviatedHandshake){
					handshakeState = Constants.STATE_HANDSHAKE_HELLO;
					transmissionState = Constants.STATE_TRANSMISSION_SEND;
					tlsState = Constants.STATE_APPLET_APPLICATION_DATA;
				} else {
					handshakeState = Constants.STATE_HANDSHAKE_CHANGE_CIPHER_SPEC;
					transmissionState = Constants.STATE_TRANSMISSION_RECEIVE;
				}
				outgoingRecordDataOffset = RecordTools.writeFinished(outgoingRecordData, outgoingRecordDataOffset);

				return wrapRecordData(outgoingRecordData, initalOutgoingOffset, (short) (outgoingRecordDataOffset - initalOutgoingOffset));
			}
			

		}
		return 0;
	}

	private void createMacHeader(byte typeByte, short contentLength){
		byte [] workspace = TransientTools.getWorkspace(this, false);
		
		TlsTools.sendSequenceCounter.copy(workspace, (short) 0);
		
		
		workspace[8] = typeByte;
		Util.setShort(workspace, (short) 9, Constants.TLS_VERSION);
		Util.setShort(workspace, (short) 11, contentLength);
		TlsTools.payloadMac.init(TlsTools.keyMac);
		TlsTools.payloadMac.update(workspace, (short) 0, Constants.LENGTH_TLS_MAC_HEADER);
		TransientTools.freeWorkspace(workspace);
	}
	
	private short doMac(byte[] outgoingRecordData,
			short outgoingRecordDataOffset, short outgoingRecordDataLength) {
		if (TlsTools.payloadMac != null) {
			short contentLengthOffset = (short) (outgoingRecordDataOffset + Constants.OFFSET_TLS_RECORD_LENGTH);
			short contentLength = Util.getShort(outgoingRecordData, contentLengthOffset);
			
			createMacHeader(outgoingRecordData[(short)(Constants.OFFSET_TLS_RECORD_TYPE_BYTE + outgoingRecordDataOffset)], contentLength);
			short maclength = TlsTools.payloadMac.doFinal(outgoingRecordData, (short) (outgoingRecordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER), (short) (outgoingRecordDataLength - Constants.LENGTH_TLS_RECORD_HEADER), outgoingRecordData,
					(short) (outgoingRecordDataOffset + outgoingRecordDataLength));
			return (short) (outgoingRecordDataLength + maclength);
		}
		return outgoingRecordDataLength;
	}
	
	private short checkMac(byte [] dataToCheck, short dataToCheckOffset, short dataToCheckLength){
		if (TlsTools.payloadMac != null){
			short contentLengthOffset = (short) (dataToCheckOffset + Constants.OFFSET_TLS_RECORD_LENGTH);
			short contentLength = (short) (Util.getShort(dataToCheck, contentLengthOffset) - TlsTools.payloadMac.getLength());
			byte typeByte = dataToCheck[(short) (Constants.OFFSET_TLS_RECORD_TYPE_BYTE + dataToCheckOffset)];
			dataToCheckOffset += Constants.LENGTH_TLS_RECORD_HEADER;
			dataToCheckLength -= Constants.LENGTH_TLS_RECORD_HEADER + TlsTools.payloadMac.getLength();
			createMacHeader(typeByte, contentLength);
			byte [] expectedMac = TransientTools.getWorkspace(this, false);
			TlsTools.payloadMac.doFinal(dataToCheck, dataToCheckOffset, dataToCheckLength, expectedMac,
					(short) 0);
			boolean macIsCorrect = 0==Util.arrayCompare(dataToCheck, (short) (dataToCheckOffset + dataToCheckLength), expectedMac, (short)0, TlsTools.payloadMac.getLength());
			TransientTools.freeWorkspace(expectedMac);
			if (!macIsCorrect){
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			return (short) (dataToCheckLength + Constants.LENGTH_TLS_RECORD_HEADER);
		}
		return dataToCheckLength;
	}
	
	private short wrapRecordData(byte[] outgoingRecordData,
			short outgoingRecordDataOffset, short outgoingRecordDataLength) {
		outgoingRecordDataLength = doMac(outgoingRecordData, outgoingRecordDataOffset, outgoingRecordDataLength);
		outgoingRecordDataLength = encryptRecordPayload(outgoingRecordData, outgoingRecordDataOffset, outgoingRecordDataLength);
		resetRecordHeaderLength(outgoingRecordData, outgoingRecordDataOffset, (short) (outgoingRecordDataLength - Constants.LENGTH_TLS_RECORD_HEADER));
		TlsTools.sendSequenceCounter.value++;
		return outgoingRecordDataLength;
	}

	private short unwrapRecordData(byte[] incomingRecordData,
			short incomingRecordDataOffset, short incomingRecordDataLength) {
		incomingRecordDataLength = decryptRecordPayload(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
		incomingRecordDataLength = checkMac(incomingRecordData, incomingRecordDataOffset, incomingRecordDataLength);
		resetRecordHeaderLength(incomingRecordData, incomingRecordDataOffset, (short) (incomingRecordDataLength - Constants.LENGTH_TLS_RECORD_HEADER));
		TlsTools.sendSequenceCounter.value++;
		return incomingRecordDataLength;
	}

	private short decryptRecordPayload(byte[] incomingRecordData,
			short incomingRecordDataOffset, short incomingRecordDataLength) {
		if (TlsTools.payloadCipher != null){
			TlsTools.payloadCipher.init(TlsTools.payloadKey, Cipher.MODE_DECRYPT, incomingRecordData, (short) (incomingRecordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER), TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
			short cipherTextOffset = (short) (incomingRecordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER + TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
			short cipherTextLength = (short) (incomingRecordDataLength - Constants.LENGTH_TLS_RECORD_HEADER - TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
			short plaintextLength = TlsTools.payloadCipher.doFinal(incomingRecordData, cipherTextOffset, cipherTextLength, incomingRecordData, cipherTextOffset);
			short paddingLength = findPaddingLengthInPlaintext(incomingRecordData, cipherTextOffset, plaintextLength);
			checkPadding(incomingRecordData, (short) (incomingRecordDataOffset + incomingRecordDataLength - paddingLength - 1), paddingLength);
			
			moveBytes(incomingRecordData, cipherTextOffset, plaintextLength, (short) - TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
			return (short) (incomingRecordDataLength - paddingLength - 1 - TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
		}
		return incomingRecordDataLength;
		
	}

	private void checkPadding(byte[] paddingData, short paddingDataOffset,
			short paddingLength) {
		for (short i = paddingDataOffset; i < (short) (paddingDataOffset + paddingLength); i++){
			if (!(paddingData[i] == paddingLength)){
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		}
	}

	private short encryptRecordPayload(byte[] outgoingRecordData,
			short outgoingRecordDataOffset, short outgoingRecordDataLength) {
		if (TlsTools.payloadCipher != null){
			outgoingRecordDataLength = createIvInRecord(outgoingRecordData, outgoingRecordDataOffset, outgoingRecordDataLength);
			TlsTools.payloadCipher.init(TlsTools.payloadKey, Cipher.MODE_ENCRYPT, outgoingRecordData, (short) (outgoingRecordDataOffset + Constants.LENGTH_TLS_RECORD_HEADER), TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
			outgoingRecordDataLength = padTlsRecord(outgoingRecordData, (short) (outgoingRecordDataOffset), outgoingRecordDataLength);
			
			short plaintextOffset = (short) (outgoingRecordDataOffset + TlsTools.LENGTH_PAYLOAD_BLOCKSIZE + Constants.LENGTH_TLS_RECORD_HEADER);
			short plaintextLength = (short) (outgoingRecordDataLength - TlsTools.LENGTH_PAYLOAD_BLOCKSIZE - Constants.LENGTH_TLS_RECORD_HEADER);
			short cipherTextLength = TlsTools.payloadCipher.doFinal(outgoingRecordData, plaintextOffset, plaintextLength, outgoingRecordData, plaintextOffset);
			outgoingRecordDataLength = (short) (plaintextOffset + cipherTextLength);
			
		}
		return outgoingRecordDataLength;
		
	}

	private void resetRecordHeaderLength(byte[] outgoingRecordData,	short outgoingRecordDataOffset, short newLength) {
		Util.setShort(outgoingRecordData, (short) (outgoingRecordDataOffset + Constants.OFFSET_TLS_RECORD_LENGTH), newLength);
	}

	private short createIvInRecord(byte[] outgoingRecordData,
			short outgoingRecordDataOffset, short outgoingRecordDataLength) {
		outgoingRecordDataOffset += Constants.LENGTH_TLS_RECORD_HEADER;
		moveBytes(outgoingRecordData, outgoingRecordDataOffset, (short) (outgoingRecordDataLength - Constants.LENGTH_TLS_RECORD_HEADER), TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
		CryptoTools.generateRandom(outgoingRecordData, outgoingRecordDataOffset, TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
		return (short) (outgoingRecordDataLength + TlsTools.LENGTH_PAYLOAD_BLOCKSIZE);
	}

	private void moveBytes(byte[] dataToMove,
			short dataToMoveOffset, short dataToMoveLength,
			short moveByNumber) {
		//TODO: find more efficient way to do this, maybe arraycopy using a ram workspace
		if (moveByNumber > 0){
			for (short i = (short) (dataToMoveOffset + dataToMoveLength); i >= dataToMoveOffset; i--){
				dataToMove[(short)(i + moveByNumber)] = dataToMove[i];
				dataToMove[i] = 0;
			}
		} else if (moveByNumber < 0){
			for (short i = dataToMoveOffset; i < (short)(dataToMoveOffset + dataToMoveLength); i++){
				dataToMove[(short)(i + moveByNumber)] = dataToMove[i];
			}
		}
		
	}

	private short padTlsRecord(byte[] recordData,
			short recordDataOffset, short recordDataLength) {
		short neededPadding = (byte) (TlsTools.LENGTH_PAYLOAD_BLOCKSIZE - (short) ( (short)(recordDataLength - Constants.LENGTH_TLS_RECORD_HEADER) % TlsTools.LENGTH_PAYLOAD_BLOCKSIZE));
		neededPadding += CryptoTools.getRandomNumber(Constants.ZERO, (short) ((short) (255 - neededPadding) / TlsTools.LENGTH_PAYLOAD_BLOCKSIZE)) * TlsTools.LENGTH_PAYLOAD_BLOCKSIZE;
		
		Util.arrayFillNonAtomic(recordData, (short) (recordDataOffset + recordDataLength), neededPadding,(byte) (neededPadding - 1));
		return (short) (recordDataLength + neededPadding);
	}

	private short findPaddingLengthInPlaintext(byte[] incomingRecordData,
			short incomingRecordDataOffset, short plaintextLength) {
		return incomingRecordData[(short)(incomingRecordDataOffset + plaintextLength - 1)];
	}

	public short readRecord(byte [] recordData, short offset, short length, byte [] payloadDestination, short payloadDestinationOffset){
		TlsTools.activateCurrentServerSecurityParameters();
		return unwrapRecordData(recordData, offset, length);
	}

	public short writeRecord(byte [] payloadData, short payloadDataOffset, short payloadDataLength, byte [] recordData, short recordDataOffset){
		TlsTools.activateCurrentClientSecurityParameters();
		short plainOffset = RecordTools.writeApplicationData(payloadData, payloadDataOffset, payloadDataLength, recordData, recordDataOffset);
		short offset = wrapRecordData(recordData, recordDataOffset, (short) (plainOffset - recordDataOffset));
		return (short) (offset - recordDataOffset);
	}
	
	private boolean checkIfAnotherMessageIsNeeded() {
		return tlsState != Constants.STATE_APPLET_APPLICATION_DATA;
	}
}
