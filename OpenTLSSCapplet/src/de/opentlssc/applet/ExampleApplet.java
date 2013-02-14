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