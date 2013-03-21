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


public class Tools {

	public static byte[] concatByteArrays(byte[]... arrays) {
		int length = 0;
		for (byte[] b : arrays) {
			length += b.length;
		}
		byte[] result = new byte[length];
		int off = 0;
		for (byte[] b : arrays) {
			for (int i = 0; i < b.length; i++) {
				result[i + off] = b[i];
			}
			off += b.length;
		}
		return result;
	}
}
