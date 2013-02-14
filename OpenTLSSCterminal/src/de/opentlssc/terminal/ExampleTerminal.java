package de.opentlssc.terminal;
import javax.smartcardio.CommandAPDU;

import de.opentlssc.terminal.communication.ApduIoComm;
import de.opentlssc.terminal.communication.Communicator;
import de.opentlssc.terminal.communication.SmartCardIoComm;
import de.opentlssc.terminal.utils.Util;


public class ExampleTerminal {


	static Communicator smartcardComm;
	static boolean pcsc = false;
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		if (args.length > 0) {
			for(String s : args){
				if (s.contains("pcsc"))
					pcsc = true;
			}
		}

		if (pcsc) {
			smartcardComm = new SmartCardIoComm();
		} else {
			smartcardComm = new ApduIoComm(new byte[] { (byte) 0x42,
					(byte) 0x6F, (byte) 0x6F, (byte) 0x6E, (byte) 0x6B,
					(byte) 0x54, (byte) 0x6C, (byte) 0x73, (byte) 0x41,
					(byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65,
					(byte) 0x74 });
		}
		
		System.out.println(Util.printResponseApduTabular(smartcardComm.sendApdu(new CommandAPDU(0x80,0,0,0))));
	}
}
