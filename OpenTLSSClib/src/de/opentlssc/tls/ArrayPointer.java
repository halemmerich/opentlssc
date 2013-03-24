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

class ArrayPointer extends DataElement {
	byte[]	data;
	short	offset;
	short	length;

	ArrayPointer(byte[] data, short offset, short length) {
		super();
		this.data = data;
		this.offset = offset;
		this.length = length;
	}

	short getAbsoluteOffset(short relativeOffset) {
		return (short) (relativeOffset + offset);
	}

	void set(byte data) {
		this.data[offset] = data;
	}

	void set(byte[] src, short srcOff) {
		Util.arrayCopyNonAtomic(src, srcOff, this.data, this.offset, this.length);
	}

	short copy(byte[] dest, short destOff) {
		Util.arrayCopyNonAtomic(data, offset, dest, destOff, length);
		return length;
	}
}
