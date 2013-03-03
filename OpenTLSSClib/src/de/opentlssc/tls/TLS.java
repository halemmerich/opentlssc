// Copyright 2013 Martin Boonk
//
// This file is part of the OpenTLSSClib.
//
// The OpenTLSSClib is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The OpenTLSSClib is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the OpenTLSSClib.  If not, see <http://www.gnu.org/licenses/>.

package de.opentlssc.tls;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class TLS {

	private short cipherSuite;
	private boolean cipherSuiteSet = false;
	
	public void setCipherSuite(short cipherSuite){
		if (isCipherSuiteValid(cipherSuite)){
			this.cipherSuite = cipherSuite;
			cipherSuiteSet = true;
		} else {
			cipherSuiteSet = false;
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}
	
	private boolean isCipherSuiteValid(short cipherSuite) {
		// TODO Auto-generated method stub
		return true;
	}

	public void initializeTls(){
		
	}
	
	public boolean isInitializationComplete(){
		return checkConfiguration();
	}
	
	private boolean checkConfiguration() {
		return cipherSuiteSet;
	}

	public boolean anotherHandshakeMessageNeeded(){
		return checkIfAnotherMessageIsNeeded();
	}
	
	/**
	 * 
	 * @param incomingRecordData
	 * @param incomingRecordDataOffset
	 * @param incomingRecordDataLength
	 * @param outgoingRecordData
	 * @param outgoingRecordDataOffset
	 * @return The expected length of the next record to be sent (worst case estimation)
	 */
	public short doHandshake(byte [] incomingRecordData, short incomingRecordDataOffset, short incomingRecordDataLength, byte [] outgoingRecordData, short outgoingRecordDataOffset){
		return calculateWorstCaseLengthOfNextRecord();
	}
	
	private short calculateWorstCaseLengthOfNextRecord() {
		// TODO Auto-generated method stub
		return 0;
	}

	public short readRecord(byte [] recordData, short offset, short length, byte [] payloadDestination, short payloadDestinationOffset){
		//FIXME
		if (!isConnectionSecure()){
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		return 0;
	}
	
	private boolean isConnectionSecure() {
		// TODO Auto-generated method stub
		return false;
	}

	public short writeRecord(byte [] payloadData, short offset, short length, byte [] recordData, short recordDataOffset){
		if (!isConnectionSecure()){
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		return 0;
	}
	
	private boolean checkIfAnotherMessageIsNeeded() {
		// TODO Auto-generated method stub
		return false;
	}
}
