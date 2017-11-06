package org.ejbca.cvc.jca;

import java.math.BigInteger;
import java.security.Key;

import org.bouncycastle.crypto.params.RSAKeyParameters;

public class JceRsaKeyParameter extends RSAKeyParameters {

    private final Key key;

    public JceRsaKeyParameter(boolean isPrivate, Key key, BigInteger modulus) {
	super(isPrivate, modulus, null);
	this.key = key;
    }

    @Override
    public BigInteger getExponent() {
	throw new UnsupportedOperationException("exponent is not available");
    }

    public Key getKey() {
	return key;
    }
}
