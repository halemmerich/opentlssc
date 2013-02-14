package de.opentlssc.terminal.communication;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Used to unify different approaches to smart card communication.
 * 
 * @author Martin Boonk
 *
 */
public interface Communicator {
	
	public abstract ResponseAPDU sendApdu(CommandAPDU apdu);

	public abstract void disconnect();

	public boolean isConnected();
}