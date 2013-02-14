package de.opentlssc.terminal.communication;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadClientInterface;
import com.sun.javacard.apduio.CadDevice;
import com.sun.javacard.apduio.CadTransportException;

import de.opentlssc.terminal.utils.Util;


/**
 * Communicate using the deprecated APDUIO from the JavaCard SDK
 * 
 * @author Martin Boonk
 *
 */
public class ApduIoComm implements Communicator {
	CadClientInterface cad;
	private boolean isConnected = false;
	
	public ApduIoComm(byte [] aid){
		createConnection();
		byte [] data=new byte[aid.length + 2];
		Util.arrayCopy(aid, 0, aid.length, data, 1);
		data[0] = (byte) (aid.length & 0xFF);
		CommandAPDU selectInst = new CommandAPDU(new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x09, (byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01, 0x7F});
		CommandAPDU create = new CommandAPDU(0x80, 0xb8, 0x00,
				0x00, data);
		CommandAPDU selectapp = new CommandAPDU(0x00, 0xa4, 0x04,
				0x00, aid);
		sendApdu(selectInst);
		sendApdu(create);
		sendApdu(selectapp);
		
	}
	
	public ApduIoComm() {
		createConnection();
	}
	
	private void createConnection(){


		Socket sock;

		try {
			sock = new Socket("localhost", 9025);
			InputStream is = sock.getInputStream();

			OutputStream os = sock.getOutputStream();

			cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
			cad.powerUp();
			isConnected = true;
		} catch (UnknownHostException e) {
			System.out.println(e.getMessage());
		} catch (IOException e) {
			System.out.println(e.getMessage());
		} catch (CadTransportException e) {
			System.out.println(e.getMessage());
		}
	}

	public void disconnect() {
		if (isConnected) {
			try {
				cad.powerDown();
				isConnected = false;
			} catch (IOException e) {
				System.out.println(e.getMessage());
			} catch (CadTransportException e) {
				System.out.println(e.getMessage());
			}
		}
	}

	public ResponseAPDU sendApdu(CommandAPDU command) {
		if (isConnected) {
			Apdu apdu = new Apdu();
			apdu.setDataIn(command.getData());
			byte[] header = new byte[7];
			header[0] = (byte) (command.getCLA() & 0xFF);
			header[1] = (byte) (command.getINS() & 0xFF);
			header[2] = (byte) (command.getP1() & 0xFF);
			header[3] = (byte) (command.getP2() & 0xFF);

			if (0 < command.getNc() && command.getNc() < 255) {
				header[4] = (byte) (command.getNc() & 0xFF);
			} else {
				header[4] = (byte) (command.getNc() & 0xFF);
				header[5] = (byte) ((command.getNc() >> 8) & 0xFF);
				header[6] = (byte) ((command.getNc() >> 16) & 0xFF);
			}

			apdu.command = header;
			try {
				cad.exchangeApdu(apdu);
			} catch (IOException | CadTransportException e) {
				System.out.println(e.getMessage());
			}

			byte[] apduout = apdu.getDataOut();
			byte[] sw = apdu.getSw1Sw2();
			byte[] response = new byte[apduout.length + 2];
			for (int i = 0; i < response.length; i++) {
				if (i < apduout.length) {
					response[i] = apduout[i];
				} else {
					response[i] = sw[i - apduout.length];
				}
			}

			ResponseAPDU r = new ResponseAPDU(response);

			return r;
		}
		return null;
	}

	public boolean isConnected() {
		return isConnected();
	}



}
