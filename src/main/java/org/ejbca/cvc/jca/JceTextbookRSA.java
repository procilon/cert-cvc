package org.ejbca.cvc.jca;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class JceTextbookRSA implements AsymmetricBlockCipher {

    private final Cipher cipher;
    private int bitSize;
    private boolean initialized = false;

    public JceTextbookRSA(String provider) throws GeneralSecurityException {
	cipher = Cipher.getInstance("RSA/ECB/NoPadding", provider);
    }

    @Override
    public void init(boolean forEncryption, CipherParameters param) {
	if (param instanceof JceRsaKeyParameter) {
	    JceRsaKeyParameter rsaParam = (JceRsaKeyParameter) param;
	    try {
		cipher.init(forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, rsaParam.getKey());
		bitSize = rsaParam.getModulus().bitLength();
	    } catch (InvalidKeyException e) {
		throw new IllegalArgumentException(e);
	    }
	} else {
	    throw new IllegalArgumentException("expected parameters with java.security.Key");
	}
	initialized = true;
    }

    @Override
    public int getInputBlockSize() {
	ensureInitialized();
	return bitSize / 8;
    }

    @Override
    public int getOutputBlockSize() {
	ensureInitialized();
	return bitSize / 8;
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int len) throws InvalidCipherTextException {
	ensureInitialized();
	try {
	    return cipher.doFinal(in, inOff, len);
	} catch (GeneralSecurityException e) {
	    throw new InvalidCipherTextException("failed to perform cipher operation", e);
	}
    }

    private void ensureInitialized() {
	if (!initialized) {
	    throw new IllegalStateException("not initialized");
	}
    }

}
