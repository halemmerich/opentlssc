// Copyright 2013 Martin Boonk
//
// This file is part of the OpenTLSSCapplet.
//
// The OpenTLSSCapplet is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The OpenTLSSCapplet is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the OpenTLSSCapplet.  If not, see <http://www.gnu.org/licenses/>.

package de.opentlssc.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacardx.apdu.ExtendedLength;
import de.opentlssc.tls.TLS;

public class ExampleApplet extends Applet implements ExtendedLength {

	TLS tls;
	byte [] workspace;
	byte [] appData;
	static boolean emu = false;
	
	public ExampleApplet() {
		detectJCWDE();
		
		tls = new TLS();
		workspace = new byte [2000];
		appData = new byte [200];
		Util.arrayFillNonAtomic(appData, (short)0, (short) (appData.length -1), (byte) 0x61);
		appData[(short)(appData.length-1)] = 0x0a;
		// all initializations must take place before the call to register(), if this hint
		// is not followed, exceptions thrown while installing might be lost unnoticed.
		register();
	}
	
	private void detectJCWDE() {
		try{
			MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
		} catch (Exception e){
			emu = true;
		}
	}

	/** 
	 * While installing the cap file on the card this method instantiates the applet.
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ExampleApplet();
				

	}	
	
	public static final byte INS_TLS_RECORD = 0;
	
	private static final byte STATE_INIT_TLS = 0;
	private static final byte STATE_FULL_HANDSHAKE = 1;
	private static final byte STATE_SEND_APP_DATA_RECORD = 2;
	private static final byte STATE_RECEIVE_APP_DATA_RECORD = 3;
	private static final byte STATE_REINIT_TLS = 4;
	private static final byte STATE_ABBREVIATED_HANDSHAKE = 5;
	private static final byte STATE_CLOSE_CONNECTION = 6;
	private static final byte STATE_FINISHED = 7;
	
	public void process(APDU apdu) throws ISOException {
		byte [] buffer = apdu.getBuffer();
		
		if (buffer[ISO7816.OFFSET_INS] == INS_TLS_RECORD){
			doTLS(apdu);
		}
	}
	
	private byte state = 0;
	private int applicationDataCounter = 0;
	
	private void doTLS(APDU apdu){
		short incomingLength = receiveExtended(apdu, workspace, (short) 0);
		short responseApduDataLength = 0;
		
		switch (state){
		case STATE_INIT_TLS:
			tls.initializeTls();
			applicationDataCounter = 0;
			state = STATE_FULL_HANDSHAKE;
			break;
		case STATE_FULL_HANDSHAKE:
			if (tls.anotherHandshakeMessageNeeded()){
				responseApduDataLength = tls.doHandshake(workspace, (short) 0, incomingLength, workspace, (short) 0);
			} else {
				state = STATE_SEND_APP_DATA_RECORD;
			}
			break;
		case STATE_SEND_APP_DATA_RECORD:
			Util.arrayFillNonAtomic(workspace, (short)0, (short) workspace.length, (byte) 0);
			responseApduDataLength = tls.writeRecord(appData, (short) 0, (short) appData.length, workspace, (short) 0);
			applicationDataCounter++;
			state = STATE_RECEIVE_APP_DATA_RECORD;
			break;
		case STATE_RECEIVE_APP_DATA_RECORD:
			if (incomingLength > apdu.getOffsetCdata()){
				tls.readRecord(workspace, (short) 0, incomingLength, workspace, (short) 0);
			}
			if (applicationDataCounter == 3) {
				state = STATE_CLOSE_CONNECTION;
			} else {
				state = STATE_REINIT_TLS;
			}
			break;
		case STATE_REINIT_TLS:
			tls.initHandshake();
			state = STATE_ABBREVIATED_HANDSHAKE;
			break;
		case STATE_ABBREVIATED_HANDSHAKE:
			if (tls.anotherHandshakeMessageNeeded()){
				responseApduDataLength = tls.doHandshake(workspace, (short) 0, incomingLength, workspace, (short) 0);
			} else {
				state = STATE_SEND_APP_DATA_RECORD;
			}
			break;
		case STATE_CLOSE_CONNECTION:
			responseApduDataLength = tls.closeConnection(workspace, (short) 0);
			state = STATE_FINISHED;
			break;
		case STATE_FINISHED:
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			break;
		}
		
		if (responseApduDataLength > 0){
			sendExtended(apdu, workspace, (short) 0, responseApduDataLength);
		}
	}
	
	private static short receiveExtended(APDU apdu, byte[] destination, short destinationOffset) {
		short inBuffer;
		short received;
		// FIXME REMOVE hack
		// FIXME: find cause of the error while running in emulator
		if (emu && apdu.getIncomingLength() == 0) {
			inBuffer = 0;
			return 0;
		}// end of hack
		inBuffer = apdu.setIncomingAndReceive();
		received = inBuffer;
		
		Util.arrayCopyNonAtomic(apdu.getBuffer(), apdu.getOffsetCdata(), destination, destinationOffset, inBuffer);
		
		while (apdu.getCurrentState() == APDU.STATE_PARTIAL_INCOMING) {
			inBuffer = apdu.receiveBytes((short) 0);
			Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, destination, received, inBuffer);
			received += inBuffer;
		}
		return received;
	}
	
	static void sendExtended(APDU apdu, byte[] data, short offset, short length) {
		apdu.setOutgoing();
		apdu.setOutgoingLength(length);
		byte[] buffer = apdu.getBuffer();
		while (length > 0) {
			if (length < (short) buffer.length) {
				// check if sending directly from buffer is required
				if (data != buffer) {
					// different array, copy to buffer and send
					Util.arrayCopyNonAtomic(data, offset, buffer, (short) 0,
							length);
					apdu.sendBytes((short) 0, length);
				} else {
					// send directly from buffer
					apdu.sendBytes(offset, length);
				}
				break;
			} else {
				// length is longer than buffer, so sending directly from
				// buffer is not possible
				Util.arrayCopyNonAtomic(data, offset, buffer, (short) 0,
						(short) buffer.length);

				apdu.sendBytes((short) 0, (short) buffer.length);
				length -= (short) buffer.length;
				offset += (short) buffer.length;
			}
		}

	}
}