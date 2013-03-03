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
import java.util.Collection;
import java.util.Iterator;
import java.util.Queue;

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
	private static Queue<Byte> inBuffer = new Queue<Byte>() {
		
		@Override
		public <T> T[] toArray(T[] arg0) {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public Object[] toArray() {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public int size() {
			// TODO Auto-generated method stub
			return 0;
		}
		
		@Override
		public boolean retainAll(Collection<?> arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public boolean removeAll(Collection<?> arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public boolean remove(Object arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public Iterator<Byte> iterator() {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public boolean isEmpty() {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public boolean containsAll(Collection<?> arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public boolean contains(Object arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public void clear() {
			// TODO Auto-generated method stub
			
		}
		
		@Override
		public boolean addAll(Collection<? extends Byte> arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public Byte remove() {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public Byte poll() {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public Byte peek() {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public boolean offer(Byte arg0) {
			// TODO Auto-generated method stub
			return false;
		}
		
		@Override
		public Byte element() {
			// TODO Auto-generated method stub
			return null;
		}
		
		@Override
		public boolean add(Byte arg0) {
			// TODO Auto-generated method stub
			return false;
		}
	};
	
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
			smartcardComm = new ApduIoComm(new byte[] { (byte) 0x42,
					(byte) 0x6F, (byte) 0x6F, (byte) 0x6E, (byte) 0x6B,
					(byte) 0x54, (byte) 0x6C, (byte) 0x73, (byte) 0x41,
					(byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65,
					(byte) 0x74 });
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
				if (sendTlsApdu(toSend).getSW() != 0x9000){
					break;
				}
				
			} else {
				if (sendTlsApdu().getSW() != 0x9000){
					break;
				}
			}
		}
	}
	

	private static ResponseAPDU sendTlsApdu(byte [] toSend){
		ResponseAPDU response =  smartcardComm.sendApdu(new CommandAPDU(0x80,ExampleApplet.INS_TLS_RECORD,0,0, toSend));
		System.out.println(Util.printResponseApduTabular(response));
		return response;
	}
	
	private static ResponseAPDU sendTlsApdu(){
		ResponseAPDU response =  smartcardComm.sendApdu(new CommandAPDU(0x80,ExampleApplet.INS_TLS_RECORD,0,0));
		System.out.println(Util.printResponseApduTabular(response));
		return response;
	}
}
