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
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

class TlsTools {

	short LENGTH_PAYLOAD_BLOCKSIZE = 16;

	Crypto_HMAC payloadMac; // hmac
	Cipher payloadCipher; // bulk
	Key payloadKey;
	PrimitiveShort sendSequenceCounter;
	ArrayPointer keyMac;
	RSAPublicKey serverPublicKey; // key
	Crypto_Prf prf;

	private TlsSecurityParameters[] securityParameters;
	private byte currentClientSecurityParametersPointer = 0;
	private byte currentServerSecurityParametersPointer = 0;

	// statefull cipher objects for payload protection
	private Cipher cipherAes;
	private Cipher cipher3Des;

	private AESKey keyAes128;
	private DESKey key3Des;
	private AESKey keyAes256;

	private Crypto_HMAC hmacSha;
	private Crypto_HMAC hmacMd5;
	private Crypto_HMAC hmacSha256;

	private RSAPublicKey				serverPublicKey512;
	private RSAPublicKey				serverPublicKey1024;
	private RSAPublicKey				serverPublicKey2048;
	
	// exchange
	private Cipher rsa;

	private MessageDigest digestForFinishedClient;
	private MessageDigest digestForFinishedServer;

	short numberOfCipherSuites = 0;
	private Object identifier;

	boolean clientHashActive = true;
	boolean serverHashActive = true;

	TLS tls;
	
	TlsTools(TLS tls) {
		identifier = new Object();

		// algorithm for key exchange encryption
		rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

		digestForFinishedClient = MessageDigest.getInstance(
				MessageDigest.ALG_SHA_256, false);
		digestForFinishedServer = MessageDigest.getInstance(
				MessageDigest.ALG_SHA_256, false);

		prf = new Crypto_Prf();

		if (LibraryConfiguration.CONFIG_AES_128
				|| LibraryConfiguration.CONFIG_AES_256) {
			cipherAes = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
					false);
		}
		if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_3DES) {
			cipher3Des = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		}

		if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_MD5) {
			hmacSha = new Crypto_HMAC(MessageDigest.ALG_MD5);
		}

		if (LibraryConfiguration.CONFIG_SHA) {
			hmacSha = new Crypto_HMAC(MessageDigest.ALG_SHA);
		}

		if (LibraryConfiguration.CONFIG_SHA_256) {
			hmacSha256 = new Crypto_HMAC(MessageDigest.ALG_SHA_256);
		}

		if (LibraryConfiguration.CONFIG_AES_128) {
			keyAes128 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
					KeyBuilder.LENGTH_AES_128, false);
		}

		if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_AES_256) {
			keyAes256 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
					KeyBuilder.LENGTH_AES_256, false);
		}

		if (!LibraryConfiguration.emu && LibraryConfiguration.CONFIG_3DES) {
			key3Des = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
					KeyBuilder.LENGTH_DES3_3KEY, false);
		}

		securityParameters = new TlsSecurityParameters[3];

		for (short i = 0; i < securityParameters.length; i++) {
			securityParameters[i] = new TlsSecurityParameters();
		}

		serverPublicKey512 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		if (!LibraryConfiguration.emu){
			serverPublicKey1024 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
			serverPublicKey2048 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		}
		
		this.tls = tls;
		reset();
	}

	void reset() {
		digestForFinishedClient.reset();
		digestForFinishedServer.reset();

		if (key3Des != null) {
			key3Des.clearKey();
		}
		if (keyAes128 != null) {
			keyAes128.clearKey();
		}
		if (keyAes256 != null) {
			keyAes256.clearKey();
		}

		currentClientSecurityParametersPointer = 0;
		for (short i = 0; i < securityParameters.length; i++) {
			securityParameters[i].reset();
		}
	}

	void handshakeHashInit() {
		digestForFinishedClient.reset();
		digestForFinishedServer.reset();
		serverHashActive = true;
		clientHashActive = true;
	}

	void handshakeHashUpdate(byte[] buffer, short offset, short length) {
		if (clientHashActive) {
			digestForFinishedClient.update(buffer, offset, length);
		}
		if (serverHashActive) {
			digestForFinishedServer.update(buffer, offset, length);
		}
	}

	void handshakeHashFinishClient(TlsSecurityParameters state) {
		byte[] dest = tls.getTransientTools().getWorkspace(identifier, false);
		digestForFinishedClient.doFinal(dest, (short) 0, (short) 0, dest,
				Constants.ZERO);
		computeVerifyData(state, dest, Constants.ZERO);
		tls.getTransientTools().freeWorkspace(dest);
	}

	void handshakeHashFinishServer(TlsSecurityParameters state) {
		byte[] dest = tls.getTransientTools().getWorkspace(identifier, false);
		digestForFinishedServer.doFinal(dest, (short) 0, (short) 0, dest,
				Constants.ZERO);
		computeVerifyData(state, dest, Constants.ZERO);
		tls.getTransientTools().freeWorkspace(dest);
	}

	private void generatePreMasterSecret(byte[] workspace, short offset) {
		tls.getCryptoTools().random.generateData(workspace, (short) (offset + 2),
				(short) (Constants.LENGTH_PRE_MASTER_SECRET - 2));
		Util.setShort(workspace, offset, Constants.TLS_VERSION);
	}

	void generateClientRandomBytes() {
		tls.getCryptoTools().generateRandom(getNextClientSecurityParameters().clientRandomBytes);
	}

	short encryptPreMasterSecret(byte[] destination, short offset) {
		rsa.init(serverPublicKey, Cipher.MODE_ENCRYPT);

		byte[] premasterSecret = tls.getTransientTools().getWorkspace(
				this, false);
		generatePreMasterSecret(premasterSecret, Constants.ZERO);
		short length = rsa.doFinal(premasterSecret, Constants.ZERO,
				Constants.LENGTH_PRE_MASTER_SECRET, destination, offset);
		generateMasterSecret(getNextClientSecurityParameters(),
				premasterSecret, Constants.ZERO);
		tls.getTransientTools().freeWorkspace(premasterSecret);
		return length;
	}

	void createPublicKeyFromCertificate(byte [] certificateData, short certificateDataOffset) {
		short publicKeyOffset = CryptoTools.findPublicKeyOffset(certificateData, certificateDataOffset);
		serverPublicKey = tls.getCryptoTools().parse(certificateData, publicKeyOffset);
	}
	
	/**
	 * Set and activate the connection state that is depicted as the current
	 * state.
	 * 
	 * @param state
	 */
	void makeNextSecurityParametersCurrentForServer() {
		currentServerSecurityParametersPointer = (byte) ((currentServerSecurityParametersPointer + 1) % securityParameters.length);
		securityParameters[currentServerSecurityParametersPointer].serverSequenceNumber.value = 0;
	}
	void makeNextSecurityParametersCurrentForClient() {
		currentClientSecurityParametersPointer = (byte) ((currentClientSecurityParametersPointer + 1) % securityParameters.length);
		securityParameters[currentClientSecurityParametersPointer].clientSequenceNumber.value = 0;
	}
	
	private void setCryptoObjects(short cipherSuite){
		switch (cipherSuite) {
		case Constants.TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL:
			payloadCipher = null;
			payloadKey = null;
			payloadMac = null;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_MD5:
			payloadCipher = null;
			payloadKey = null;
			payloadMac = hmacMd5;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA:
			payloadCipher = null;
			payloadKey = null;
			payloadKey = null;
			payloadMac = hmacSha;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA256:
			payloadCipher = null;
			payloadKey = null;
			payloadMac = hmacSha256;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
			payloadCipher = cipher3Des;
			payloadKey = key3Des;
			payloadMac = hmacSha256;
			LENGTH_PAYLOAD_BLOCKSIZE = 8;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
			payloadCipher = cipherAes;
			payloadKey = keyAes128;
			payloadMac = hmacSha;
			LENGTH_PAYLOAD_BLOCKSIZE = 16;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
			payloadCipher = cipherAes;
			payloadKey = keyAes128;
			payloadMac = hmacSha256;
			LENGTH_PAYLOAD_BLOCKSIZE = 16;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
			payloadCipher = cipherAes;
			payloadKey = keyAes256;
			payloadMac = hmacSha;
			LENGTH_PAYLOAD_BLOCKSIZE = 16;
			break;
		case Constants.TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
			payloadCipher = cipherAes;
			payloadKey = keyAes256;
			payloadMac = hmacSha256;
			LENGTH_PAYLOAD_BLOCKSIZE = 16;
			break;
		}
	}

	private void activateClientConnectionState(TlsSecurityParameters state) {
		setCryptoObjects(state.cipherSuite);

		if (payloadKey != null) {
			switch (payloadKey.getType()) {
			case KeyBuilder.TYPE_AES:
				((AESKey) payloadKey).setKey(
						state.clientWriteKey.data, state.clientWriteKey.offset);
				break;
			case KeyBuilder.TYPE_DES:
				((DESKey) payloadKey).setKey(
						state.clientWriteKey.data, state.clientWriteKey.offset);
				break;
			}
		}

		sendSequenceCounter = state.clientSequenceNumber;
		if (state.cipherSuite != Constants.TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL){
			keyMac = state.clientMacWriteKey;	
		} else {
			keyMac = null;
		}
	}

	private void activateServerConnectionState(TlsSecurityParameters state) {
		setCryptoObjects(state.cipherSuite);
		
		if (payloadKey != null) {
			switch (payloadKey.getType()) {
			case KeyBuilder.TYPE_AES:
				((AESKey) payloadKey).setKey(
						state.serverWriteKey.data, state.serverWriteKey.offset);
				break;
			case KeyBuilder.TYPE_DES:
				((DESKey) payloadKey).setKey(
						state.serverWriteKey.data, state.serverWriteKey.offset);
				break;
			}
		}

		sendSequenceCounter = state.serverSequenceNumber;
		if (state.cipherSuite != Constants.TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL){
			keyMac = state.serverMacWriteKey;	
		} else {
			keyMac = null;
		}
	}

	void activateCurrentClientSecurityParameters(){
		activateClientConnectionState(securityParameters[currentClientSecurityParametersPointer]);
	}

	void activateNextClientSecurityParameters(){
		activateClientConnectionState(securityParameters[(currentClientSecurityParametersPointer + 1) % securityParameters.length]);
	}

	void activateCurrentServerSecurityParameters(){
		activateServerConnectionState(securityParameters[currentServerSecurityParametersPointer]);
	}

	void activateNextServerSecurityParameters(){
		activateServerConnectionState(securityParameters[(currentServerSecurityParametersPointer + 1) % securityParameters.length]);
	}
	
	TlsSecurityParameters getNextClientSecurityParameters() {
		return securityParameters[(currentClientSecurityParametersPointer + 1)
				% securityParameters.length];
	}

	TlsSecurityParameters getCurrentClientSecurityParameters() {
		return securityParameters[currentClientSecurityParametersPointer];
	}

	void generateKeyBlock(TlsSecurityParameters state) {
		byte[] workspace = tls.getTransientTools().getWorkspace(identifier, false);
		Util.arrayCopyNonAtomic(state.serverRandomBytes.data,
				state.serverRandomBytes.offset, workspace, Constants.ZERO,
				Constants.LENGTH_RANDOM_BYTES);
		Util.arrayCopyNonAtomic(state.clientRandomBytes.data,
				state.clientRandomBytes.offset, workspace,
				Constants.LENGTH_RANDOM_BYTES, Constants.LENGTH_RANDOM_BYTES);
		state.rebuild();
		prf.expand(state.keyBlock, state.masterSecret,
				Constants.labelKeyExpansion, workspace, Constants.ZERO,
				(short) (Constants.LENGTH_RANDOM_BYTES * 2),
				state.keyBlock.length);
		tls.getTransientTools().freeWorkspace(workspace);
	}

	void generateMasterSecret(TlsSecurityParameters state,
			byte[] preMasterSecret, short offset) {
		byte[] workspace = tls.getTransientTools().getWorkspace(identifier, false);
		Util.arrayCopyNonAtomic(state.clientRandomBytes.data,
				state.clientRandomBytes.offset, workspace, Constants.ZERO,
				Constants.LENGTH_RANDOM_BYTES);
		Util.arrayCopyNonAtomic(state.serverRandomBytes.data,
				state.serverRandomBytes.offset, workspace,
				Constants.LENGTH_RANDOM_BYTES, Constants.LENGTH_RANDOM_BYTES);
		prf.expand(state.masterSecret, preMasterSecret, offset,
				Constants.LENGTH_PRE_MASTER_SECRET,
				Constants.labelMasterSecret, workspace, Constants.ZERO,
				(short) (Constants.LENGTH_RANDOM_BYTES * 2), (short) 48);
		tls.getTransientTools().freeWorkspace(workspace);
	}

	void computeVerifyData(TlsSecurityParameters state,
			byte[] handshakeHash, short offset) {
		prf.expand(Data.verifyData, state.masterSecret,
				Constants.labelClientFinished, handshakeHash, offset,
				digestForFinishedClient.getLength(), Data.verifyData.length);
	}

	public void copyMasterSecretToNextSecurityParameters() {
		securityParameters[currentClientSecurityParametersPointer].masterSecret.copy(getNextClientSecurityParameters().masterSecret.data, getCurrentClientSecurityParameters().masterSecret.offset);
	}

	
	RSAPublicKey getPublicKeyForSize(short size){
		switch(size){
			case KeyBuilder.LENGTH_RSA_512:
				return serverPublicKey512;
			case KeyBuilder.LENGTH_RSA_1024:
				return serverPublicKey1024;
			case KeyBuilder.LENGTH_RSA_2048:
				return serverPublicKey2048;
			default:
				return null;
		}
	}
}