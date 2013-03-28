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

import javacard.framework.Util;

class Utilities {

	static short writeLengthField(byte [] destination, short offset, short numberOfLengthFieldBytes, short lengthFieldValue){

		
		switch (numberOfLengthFieldBytes){
		case 1:
			destination[offset] = (byte) lengthFieldValue;
			break;
		case 2:
			Util.setShort(destination, offset, lengthFieldValue);
			break;
		case 0:
			break;
		default:
			Util.arrayFillNonAtomic(destination, offset, (short) (numberOfLengthFieldBytes - 2), (byte)0x00);
			Util.setShort(destination, (short) (offset + numberOfLengthFieldBytes - 2), lengthFieldValue);
			break;
		}
		return (short) (offset + numberOfLengthFieldBytes);
	}
	
	static short setShort(byte[] dest, short destOff, short length, short value) {
		if (length == 1) {
			dest[destOff] = (byte) (value & 0xFF);
		} else if (length >= 2) {
			Util.setShort(dest, (short) (destOff + length - 2), value);
			Util.arrayFillNonAtomic(dest, destOff, (short) (length - 2), (byte) 0);
		}
		return (short) (destOff + length);
	}

	public static short buildAlert(boolean fatal, byte alertReason) {
		short alert = (short) ((fatal ? Constants.TLS_ALERT_LEVEL_FATAL: Constants.TLS_ALERT_LEVEL_WARNING) << 8);
		return (short) (alert | alertReason);
	}
}
