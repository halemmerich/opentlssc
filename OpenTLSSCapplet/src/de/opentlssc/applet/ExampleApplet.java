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
import javacard.framework.ISOException;
import javacardx.apdu.ExtendedLength;
import de.opentlssc.tls.TLS;

public class ExampleApplet extends Applet implements ExtendedLength {

	public ExampleApplet() {
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
	
	public void process(APDU apdu) throws ISOException {
		TLS tls = new TLS();
		byte test = tls.test();
		test += 1;
		ISOException.throwIt(test);
	}
}