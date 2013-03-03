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
import javacardx.apdu.ExtendedLength;
import de.opentlssc.tls.TLS;

public class ExampleApplet extends Applet implements ExtendedLength {

	TLS tls;
	byte [] workspace;
	
	public ExampleApplet() {
		tls = new TLS();
		workspace = new byte [2000];
		// all initializations must take place before the call to register(), if this hint
		// is not followed, exceptions thrown while installing might be lost unnoticed.
		register();
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
	
	public void process(APDU apdu) throws ISOException {
		ISOException.throwIt((short) 0);
		byte [] buffer = apdu.getBuffer();
		short incomingLength = (short) (apdu.setIncomingAndReceive() - apdu.getOffsetCdata());
		if (buffer[ISO7816.OFFSET_INS] == INS_TLS_RECORD){
			short responseApduDataLength = 0;
			
			if (!tls.isInitializationComplete()){
				tls.initializeTls();
			}
			if (tls.anotherHandshakeMessageNeeded()){
				responseApduDataLength = tls.doHandshake(apdu.getBuffer(), apdu.getOffsetCdata(), incomingLength, buffer, (short) 0);
			} else {
				if (incomingLength > apdu.getOffsetCdata()){
					tls.readRecord(buffer, apdu.getOffsetCdata(), incomingLength, workspace, (short) 0);
				}
				responseApduDataLength = tls.writeRecord(workspace, (short) 0, (short) 16, buffer, (short) 0);
			}
			if (responseApduDataLength > 0){
				apdu.setOutgoingAndSend((short)0 , responseApduDataLength);
			}
		}
	}
}