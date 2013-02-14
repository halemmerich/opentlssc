// Copyright 2013 Martin Boonk
//
// This file is part of the OpenTLSSCterminal.
//
// The OpenTLSSCterminal is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The OpenTLSSCterminal is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the OpenTLSSCterminal.  If not, see <http://www.gnu.org/licenses/>.

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
