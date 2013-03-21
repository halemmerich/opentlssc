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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.opentlssc.applet.ExampleApplet;
import de.opentlssc.terminal.communication.ApduIoComm;
import de.opentlssc.terminal.communication.Communicator;
import de.opentlssc.terminal.communication.SmartCardIoComm;
import de.opentlssc.terminal.utils.Util;


public class ExampleTerminal {


	static Communicator smartcardComm;
	static boolean pcsc = false;
	private static Socket echoSocket;
	private static Queue<Byte> inBuffer = new ConcurrentLinkedQueue<Byte>();
	
	/**
	 * @param args
	 * @throws IOException 
	 * @throws InterruptedException 
	 */
	public static void main(String[] args) throws IOException, InterruptedException {
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
			smartcardComm = new ApduIoComm(new byte[] { (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0x00, (byte) 0x00, (byte) 0xFF});
		}
		
		echoSocket = new Socket("localhost", 5556);
		
		doTLS();
		
		
		echoSocket.close();
		
		smartcardComm.disconnect();
	}

	private static void doTLS() throws IOException, InterruptedException {
		ResponseAPDU response = null;
		OutputStream socketOut = echoSocket.getOutputStream();
		InputStream socketIn = echoSocket.getInputStream();
		byte [] toSend;
		while (true){
			if (response != null && response.getData().length > 0){
				socketOut.write(response.getData());
				response = null;
			}
			int available = socketIn.available();
			if (available == 0){
				Thread.sleep(150);
				available = socketIn.available();
			}
			while (available > 0){
				for (int i = 0; i < available; i++){
					inBuffer.add((byte) socketIn.read());
				}
				available = socketIn.available();
			}
			
			if (inBuffer.size() >= 5){
				byte [] header = new byte [5];
				for (int i = 0; i < 5; i++){
					header[i] = inBuffer.remove();
				}
				//get length 
				int length = Util.getShort(header, 3);
				byte [] content = new byte [length];
				for (int i = 0; i < length; i++){
					content[i] = inBuffer.remove();
				}
				toSend = Tools.concatByteArrays(header, content);
				if ((response = sendTlsApdu(toSend)).getSW() != 0x9000){
					break;
				}
				
			} else {
				if ((response = sendTlsApdu()).getSW() != 0x9000){
					break;
				}
			}
		}
	}
	

	private static ResponseAPDU sendTlsApdu(byte [] toSend){
		CommandAPDU command;
		if (toSend == null){
			command = new CommandAPDU(0x80,ExampleApplet.INS_TLS_RECORD,0,0);
		} else {
			command = new CommandAPDU(0x80,ExampleApplet.INS_TLS_RECORD,0,0, toSend);
		}
		System.out.println(Util.printCommandApduTabular(command));
		ResponseAPDU response =  smartcardComm.sendApdu(command);
		System.out.println(Util.printResponseApduTabular(response));
		return response;
	}
	
	private static ResponseAPDU sendTlsApdu(){
		return sendTlsApdu(null);
	}
}
