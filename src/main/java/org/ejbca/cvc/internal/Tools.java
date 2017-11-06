package org.ejbca.cvc.internal;

import static java.nio.ByteBuffer.allocate;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.ejbca.cvc.internal.tlv.TLV;

public class Tools {
    public static final BigInteger X509_PUBLIC_EXPONENT = new BigInteger("010001", 16);

    public static byte[] readFromBuffer(int length, ByteBuffer data) {
	byte[] result = new byte[length];
	data.get(result);
	return result;
    }

    public static RSAPublicKey toKey(BigInteger modulus, BigInteger exponent) {
	try {
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

	    return (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
	} catch (GeneralSecurityException e) {
	    throw new IllegalStateException(e);
	}
    }

    public static void ensureX509PublicRsaExponent(BigInteger number) {
	if (!X509_PUBLIC_EXPONENT.equals(number)) {
	    throw new IllegalArgumentException(
		    "expected exponent to be " + X509_PUBLIC_EXPONENT + " but was " + number);
	}
    }

    public static ByteBuffer encodedObjectIdentifier(String oid) {
	byte[] encodedOid;
	try {
	    encodedOid = new ASN1ObjectIdentifier(oid).getEncoded(ASN1Encoding.DER);

	    TLV tlv = TLV.parse(ByteBuffer.wrap(encodedOid));

	    return tlv.getValue().bytes().asReadOnlyBuffer();
	} catch (IOException e) {
	    throw new IllegalStateException(e);
	}
    }

    public static ByteBuffer expand(int length, ByteBuffer data) {
	if (data.remaining() == length) {
	    return data;
	} else if (data.remaining() > length) {
	    throw new IllegalArgumentException(data + " is larger that size " + length);
	} else {
	    data = data.duplicate();
	    int missing = length - data.remaining();
	    ByteBuffer result = allocate(length);
	    while (missing-- > 0) {
		result.put((byte) 0x00);
	    }
	    result.put(data);
	    result.rewind();
	    return result;
	}
    }

    public static ByteBuffer shrink(int length, ByteBuffer data) {
	if (data.remaining() == length) {
	    return data;
	} else if (data.remaining() < length) {
	    throw new IllegalArgumentException(data + " is smaller that size " + length);
	} else {
	    data = data.duplicate();
	    int diff = data.remaining() - length;

	    while (diff-- > 0) {
		if (data.get() != 0x00) {
		    throw new IllegalArgumentException("leading bytes are non-zero");
		}
	    }

	    return data;
	}
    }
}
