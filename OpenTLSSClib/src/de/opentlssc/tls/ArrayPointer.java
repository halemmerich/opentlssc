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

	void set(byte data, short offset) {
		this.data[offset] = data;
	}

	void set(byte data) {
		this.data[offset] = data;
	}

	void set(short data, short offset) {
		Util.setShort(this.data, (short) (this.offset + offset), data);
	}

	void set(short data) {
		Util.setShort(this.data, (short) (this.offset), data);
	}

	void set(ArrayPointer source, short offset){
		set(source.data, source.offset, offset, source.length);
	}
	
	void set(byte[] src, short srcOff, short offset, short length) {
		Util.arrayCopyNonAtomic(src, srcOff, this.data, (short) (this.offset + offset), length);
	}

	void set(byte[] src, short srcOff) {
		Util.arrayCopyNonAtomic(src, srcOff, this.data, this.offset, this.length);
	}

	short copy(byte[] dest, short destOff) {
		Util.arrayCopyNonAtomic(data, offset, dest, destOff, length);
		return length;
	}

	byte compare(byte[] data, short offset, short length) {
		return Util.arrayCompare(this.data, this.offset, data, offset, length);
	}

	byte compare(byte[] data, short offset) {
		return Util.arrayCompare(this.data, this.offset, data, offset, this.length);
	}

	void fill() {
		Util.arrayFillNonAtomic(data, offset, length, (byte) 0x00);
	}

	byte getByte() {
		return data[offset];
	}

	short getShort() {
		return Util.getShort(data, offset);
	}
}
