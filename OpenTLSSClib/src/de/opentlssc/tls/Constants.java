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

/**
 * Contains all used constants.
 * 
 * @author Martin Boonk
 *
 */
public class Constants extends StaticTool{
	public static final byte	CLA													= (byte) 0x80;

	public static final byte	INS_WORK											= 0x10;
	public static final byte	INS_INITIATE										= 0x20;
	public static final byte	INS_GET_CONFIGURATIONS								= 0x30;
	public static final byte	INS_SET_CONFIGURATION								= 0x31;
	public static final byte	INS_PERSO_PIN										= 0x40;
	public static final byte	INS_PERSO_DATA										= 0x41;
	public static final byte	INS_USER_PIN										= 0x42;

	public static final byte	INS_DEBUG_DUMP_ARRAY								= (byte) 0xFF;
	public static final byte	INS_DEBUG_TEST2										= (byte) 0xFE;
	public static final byte	INS_DEBUG_INITIATE									= (byte) 0xFD;
	public static final byte	INS_DEBUG_DUMP										= (byte) 0xFC;
	public static final byte	INS_DEBUG_SET_EMU									= (byte) 0xFB;
	public static final byte	INS_DEBUG_GET_EXCEPTION_HISTORY						= (byte) 0xFA;
	public static final byte	INS_DEBUG_RENEGOTIATE								= (byte) 0xF9;
	public static final byte	INS_DEBUG_INFO										= (byte) 0xF8;

	public static final byte	RESPONSE_TYPE_DEBUG									= 0x00;
	public static final byte	RESPONSE_TYPE_DEBUG_DUMP_TLS						= (byte) 0xF0;
	public static final byte	RESPONSE_TYPE_DEBUG_DUMP_ARRAY						= (byte) 0xE0;
	public static final byte	RESPONSE_TYPE_DEBUG_EXCEPTION_HISTORY				= (byte) 0xD0;
	public static final byte	RESPONSE_TYPE_TLS_RECORD							= 0x10;
	public static final byte	RESPONSE_TYPE_EMPTY									= 0x20;
	public static final byte	RESPONSE_TYPE_CONFIGURATION_LIST					= 0x30;

	public static final byte	TLV_TYPE_ENTRY = 0;
	public static final byte 	TLV_TYPE_HOSTNAME = 1;
	public static final byte 	TLV_TYPE_PORT = 2;
	public static final byte	TLV_TYPE_DATA	= 3;
	public static final byte	TLV_TYPE_CONFIG	= 4;
	public static final byte	TLV_TYPE_PERSO_DATA	= 5;
	public static final byte	TLV_TYPE_ID	= 6;
	
	// TLS constants
	static final byte	TLS_COMPRESSION_METHOD_NULL							= 0;
	static final byte	TLS_MAC_ALGORITHM_NULL								= 0;
	static final byte	TLS_MAC_ALGORITHM_HMAC_SHA_1						= 0;
	static final byte	TLS_MAC_ALGORITHM_HMAC_SHA_256						= 0;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_HELLO_REQUEST			= 0;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_HELLO				= 1;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO				= 2;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_CERTIFICATE				= 11;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_SERVER_KEY_EXCHANGE		= 12;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_CERTIFICATE_REQUEST		= 13;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO_DONE		= 14;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_CERTIFICATE_VERIFY		= 15;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_KEY_EXCHANGE		= 16;
	public static final byte	TLS_HANDSHAKE_CONTENT_TYPE_FINISHED					= 20;
	public static final byte	TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC_VALUE	= 20;
	public static final byte	TLS_RECORD_CONTENT_TYPE_ALERT_VALUE					= 21;
	public static final byte	TLS_RECORD_CONTENT_TYPE_HANDSHAKE_VALUE				= 22;
	public static final byte	TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA_VALUE		= 23;

	static final short	TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL				= 0x0000;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA			= 0x002F;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256		= 0x003C;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA			= 0x0035;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256		= 0x003D;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA			= 0x000A;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_NULL_MD5					= 0x0001;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA					= 0x0002;
	static final short	TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA256				= 0x003B;

	static final byte	TLS_ALERT_LEVEL_WARNING								= 1;
	static final byte	TLS_ALERT_LEVEL_FATAL								= 2;
	static final byte	TLS_ALERT_REASON_CLOSE_NOTIFY						= 0;
	static final byte	TLS_ALERT_REASON_UNEXPECTED_MESSAGE					= 10;
	static final byte	TLS_ALERT_REASON_BAD_RECORD_MAC						= 20;
	static final byte	TLS_ALERT_REASON_HANDSHAKE_FAILURE					= 40;
	static final byte	TLS_ALERT_REASON_PROTOCOLL_VERSION					= 70;
	static final byte	TLS_ALERT_REASON_INTERNAL_ERROR						= 80;

	// Applet states

	static final byte	STATE_APPLET_UNINITIALIZED							= 0;
	static final byte	STATE_APPLET_HANDSHAKE								= 60;
	static final byte	STATE_HANDSHAKE_HELLO								= 1;
	static final byte	STATE_HANDSHAKE_FINISHED							= 40;
	static final byte	STATE_HANDSHAKE_CHANGE_CIPHER_SPEC					= 41;
	static final byte	STATE_HANDSHAKE_CERTIFICATE							= 6;
	static final byte	STATE_HANDSHAKE_HELLO_DONE							= 7;
	static final byte	STATE_HANDSHAKE_KEY_EXCHANGE						= 8;
	static final byte	STATE_APPLET_APPLICATION_DATA						= 50;
	static final byte	STATE_APPLET_CLOSE_CONNECTION						= (byte) 255;
	static final byte	STATE_APPLET_ERROR									= 100;
	static final byte	STATE_APPLET_CONNECTION_CLOSED								= 101;
	static final byte	STATE_TRANSMISSION_NONE								= 0;
	static final byte	STATE_TRANSMISSION_SEND								= 1;
	static final byte	STATE_TRANSMISSION_RECEIVE							= 2;

	static final short	LENGTH_TLS_RECORD_HEADER							= 5;
	static final short	LENGTH_TLS_HANDSHAKE_HEADER							= 4;
	static final short	LENGTH_RANDOM_BYTES									= 32;
	static final short	LENGTH_EXTENSIONS_LENGTH							= 2;
	static final short	LENGTH_CIPHER_SUITES_LENGTH							= 2;
	static final short	LENGTH_SESSIONID_LENGTH								= 1;
	static final short	LENGTH_COMPRESSION_METHODS_LENGTH					= 1;
	static final short	LENGTH_ENCRYPTED_PRE_MASTER_SECRET_LENGTH			= 2;
	static final short	LENGTH_MASTER_SECRET								= 48;
	static final short	LENGTH_PRE_MASTER_SECRET							= 48;

	// tls data (received/to send)
	static final short	OFFSET_COMPRESSION_METHODS							= 0;
	static final short	LENGTH_COMPRESSION_METHODS							= 1;

	static final short	OFFSET_EXTENSIONS									= OFFSET_COMPRESSION_METHODS
																					+ LENGTH_COMPRESSION_METHODS;
	static final short	LENGTH_EXTENSIONS									= 0;


	static final short	OFFSET_SESSIONID									= OFFSET_EXTENSIONS
																					+ LENGTH_EXTENSIONS;
	static final short	LENGTH_SESSIONID									= 32;

	static final short	OFFSET_SERVER_CERTIFICATE							= OFFSET_SESSIONID + LENGTH_SESSIONID;
	// tls security related

	static final short	OFFSET_VERIFY_DATA									= (short) (OFFSET_SERVER_CERTIFICATE + LibraryConfiguration.CONFIG_LENGTH_SERVER_CERTIFICATE);
	static final short	LENGTH_VERIFY_DATA									= 12;

	// temporary

	static final short	DATA_SIZE											= OFFSET_VERIFY_DATA + LENGTH_VERIFY_DATA;

	// labels for prf
	static final short	OFFSET_LABEL_KEY_EXPANSION							= 0;
	static final short	LENGTH_LABEL_KEY_EXPANSION							= 13;
	static final short	OFFSET_LABEL_CLIENT_FINISHED						= OFFSET_LABEL_KEY_EXPANSION
														+ LENGTH_LABEL_KEY_EXPANSION;
	static final short	LENGTH_LABEL_CLIENT_FINISHED						= 15;

	static final short	OFFSET_LABEL_SERVER_FINISHED						= OFFSET_LABEL_CLIENT_FINISHED
																					+ LENGTH_LABEL_CLIENT_FINISHED;
	static final short	LENGTH_LABEL_SERVER_FINISHED						= 15;

	static final short	OFFSET_LABEL_MASTER_SECRET							= OFFSET_LABEL_SERVER_FINISHED
																					+ LENGTH_LABEL_SERVER_FINISHED;
	static final short	LENGTH_LABEL_MASTER_SECRET							= 13;

	static byte[]	LABELS;

	static final short	TLS_VERSION											= 0x0303;

	static final short	OFFSET_TLS_CERTIFICATE_LENGTH_IN_RECORD				= LENGTH_TLS_RECORD_HEADER + LENGTH_TLS_HANDSHAKE_HEADER + 3;
	static final short	OFFSET_TLS_CERTIFICATE_DATA_IN_RECORD				= OFFSET_TLS_CERTIFICATE_LENGTH_IN_RECORD + 3;
	static final short	OFFSET_TLS_FINISHED_IN_RECORD									= LENGTH_TLS_RECORD_HEADER + LENGTH_TLS_HANDSHAKE_HEADER;
	static final short	OFFSET_TLS_RECORD_LENGTH							= 3;
	static final short	OFFSET_TLS_RECORD_TYPE_BYTE							= 0;
	static final short	OFFSET_TLS_HANDSHAKE_LENGTH_IN_RECORD							= 1;
	static final short	LENGTH_TLS_ALERT									= 2;
	static final short	LENGTH_TLS_MAC_HEADER								= 13;

	static final short	ZERO												= 0;






	static ArrayPointer				labelMasterSecret;
	static ArrayPointer				labelClientFinished;
	static ArrayPointer				labelServerFinished;
	static ArrayPointer				labelKeyExpansion;
	
	static void init(){
		LABELS = new byte[] {
				// "key expansion"
				(byte) 0x6B, (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x65, (byte) 0x78, (byte) 0x70, (byte) 0x61,
				(byte) 0x6E, (byte) 0x73, (byte) 0x69,
				(byte) 0x6F,
				(byte) 0x6E,
				// "client finished"
				(byte) 0x63, (byte) 0x6C, (byte) 0x69, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x20, (byte) 0x66,
				(byte) 0x69, (byte) 0x6E, (byte) 0x69, (byte) 0x73, (byte) 0x68, (byte) 0x65,
				(byte) 0x64,
				// "server finished"
				(byte) 0x73, (byte) 0x65, (byte) 0x72, (byte) 0x76, (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x66,
				(byte) 0x69, (byte) 0x6E, (byte) 0x69, (byte) 0x73, (byte) 0x68, (byte) 0x65, (byte) 0x64,
				// "master secret"
				(byte) 0x6D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x73,
				(byte) 0x65, (byte) 0x63, (byte) 0x72, (byte) 0x65, (byte) 0x74 };
		labelMasterSecret = new ArrayPointer(Constants.LABELS, Constants.OFFSET_LABEL_MASTER_SECRET, Constants.LENGTH_LABEL_MASTER_SECRET);
		labelClientFinished = new ArrayPointer(Constants.LABELS, Constants.OFFSET_LABEL_CLIENT_FINISHED, Constants.LENGTH_LABEL_CLIENT_FINISHED);
		labelServerFinished = new ArrayPointer(Constants.LABELS, Constants.OFFSET_LABEL_SERVER_FINISHED, Constants.LENGTH_LABEL_SERVER_FINISHED);
		labelKeyExpansion = new ArrayPointer(Constants.LABELS, Constants.OFFSET_LABEL_KEY_EXPANSION, Constants.LENGTH_LABEL_KEY_EXPANSION);

	}

}
