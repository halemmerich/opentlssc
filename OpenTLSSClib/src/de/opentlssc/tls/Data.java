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

class Data extends StaticTool{
	static byte[]						DATA;

	static ArrayPointer	cipherSuites;
	static ArrayPointer	compressionMethods;
	static ArrayPointer	sessionId;

	static ArrayPointer				extensions;
	static ArrayPointer				serverCertificate;
	static ArrayPointer				verifyData;
	static ArrayPointer				temp;
	static ArrayPointer				cryptoTemp;

	static short compressionMethod;

	//FIXME: REMOVE
	static byte [] debug;
	static short debugpointer = 0; 
	
	static void reset(){
		Util.arrayFillNonAtomic(DATA, (short) 0,(short) DATA.length, (byte) 0x00);
		
		// set values
		compressionMethods.set(Constants.TLS_COMPRESSION_METHOD_NULL);
		

		sessionId.length = 0;
	}
	
	static void init() {
		DATA = new byte[Constants.DATA_SIZE];
		debug = new byte [1000];
		compressionMethods = new ArrayPointer(DATA, Constants.OFFSET_COMPRESSION_METHODS, Constants.LENGTH_COMPRESSION_METHODS);
		sessionId = new ArrayPointer(DATA, Constants.OFFSET_SESSIONID, Constants.LENGTH_SESSIONID);
		extensions = new ArrayPointer(DATA, Constants.OFFSET_EXTENSIONS, Constants.LENGTH_EXTENSIONS);
		serverCertificate = new ArrayPointer(DATA, Constants.OFFSET_SERVER_CERTIFICATE, LibraryConfiguration.CONFIG_LENGTH_SERVER_CERTIFICATE);
		verifyData = new ArrayPointer(DATA, Constants.OFFSET_VERIFY_DATA, Constants.LENGTH_VERIFY_DATA);
		reset();
	}
}
