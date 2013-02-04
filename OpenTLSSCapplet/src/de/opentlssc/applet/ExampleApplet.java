package de.opentlssc.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacardx.apdu.ExtendedLength;

public class ExampleApplet extends Applet implements ExtendedLength {

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
		// TODO Auto-generated method stub

	}
}