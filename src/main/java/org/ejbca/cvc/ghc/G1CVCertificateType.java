package org.ejbca.cvc.ghc;

import static java.nio.ByteBuffer.wrap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.security.interfaces.RSAPublicKey;

import org.ejbca.cvc.internal.Tools;

/**
 * Section 8.1 eGK specification Part 1 v2.2.0
 * 
 * @see https://www.gematik.de/cms/media/dokumente/release_0_5_3/release_0_5_3_egk/gematik_eGK_Spezifikation_Teil1_V2_2_0.pdf
 * 
 * @author fichtelmannm
 *
 */
public enum G1CVCertificateType implements G1CertificateDataParser, G1CertificateGenerator, G1CertificateDataValidator {
    AUTHENTICATION_CERTIFICATE((byte) 0x22, "1.3.36.3.5.2.4") {
	@Override
	public G1CertificateData parse(ByteBuffer data) {
	    data = data.duplicate();
	    byte cpi = data.get();
	    if (cpi != getProfileIdentifier()) {
		throw new IllegalArgumentException("CPI is not " + getProfileIdentifier());
	    }
	    byte[] modulus = Tools.readFromBuffer(256, data);
	    int exponent = data.getInt();
	    validateOid(data);
	    byte[] cha = Tools.readFromBuffer(7, data);
	    byte[] chr = Tools.readFromBuffer(12, data);
	    byte[] car = Tools.readFromBuffer(8, data);

	    if (data.hasRemaining()) {
		throw new IllegalArgumentException("data remaining, expected EOF");
	    }

	    return new G1CertificateData(Tools.toKey(new BigInteger(1, modulus), BigInteger.valueOf(exponent)),
		    wrap(car), wrap(chr), wrap(cha));
	}

	@Override
	public ByteBuffer generate(G1CertificateData data) throws IOException {
	    RSAPublicKey entityKey = data.getPublicKey();

	    ByteArrayOutputStream tbs = new ByteArrayOutputStream();
	    WritableByteChannel channel = Channels.newChannel(tbs);

	    tbs.write(getProfileIdentifier() & 0xFF);
	    channel.write(Tools.shrink(256, wrap(entityKey.getModulus().toByteArray())));
	    channel.write(Tools.expand(4, wrap(entityKey.getPublicExponent().toByteArray())));
	    channel.write(taId());
	    channel.write(data.cha());
	    channel.write(data.chr());
	    channel.write(data.car());

	    return wrap(tbs.toByteArray());
	}

	@Override
	public void validate(G1CertificateData data) {
	    if (data.car().remaining() != 8) {
		throw new IllegalArgumentException("CAR must be 8 byte");
	    }
	    if (data.chr().remaining() != 12) {
		throw new IllegalArgumentException("CHR must be 12 byte");
	    }
	    if (data.cha() == null) {
		throw new IllegalArgumentException("CHA missing, but required");
	    }
	    if (data.cha().remaining() != 7) {
		throw new IllegalArgumentException("CHA must be 7 byte");
	    }

	    Tools.ensureX509PublicRsaExponent(data.getPublicKey().getPublicExponent());
	}
    },

    CA_CERTIFICATE((byte) 0x21, "1.3.36.3.4.2.2.4") {
	@Override
	public G1CertificateData parse(ByteBuffer data) {
	    data = data.duplicate();
	    byte cpi = data.get();
	    if (cpi != getProfileIdentifier()) {
		throw new IllegalArgumentException("CPI is not " + getProfileIdentifier());
	    }
	    byte[] modulus = Tools.readFromBuffer(256, data);
	    int exponent = data.getInt();
	    validateOid(data);
	    byte[] chr = Tools.readFromBuffer(8, data);
	    byte[] car = Tools.readFromBuffer(8, data);

	    if (data.hasRemaining()) {
		throw new IllegalArgumentException("data remaining, expected EOF");
	    }

	    return new G1CertificateData(Tools.toKey(new BigInteger(1, modulus), BigInteger.valueOf(exponent)),
		    wrap(car), wrap(chr));
	}

	@Override
	public ByteBuffer generate(G1CertificateData data) throws IOException {
	    ByteArrayOutputStream tbs = new ByteArrayOutputStream();
	    WritableByteChannel channel = Channels.newChannel(tbs);

	    tbs.write(getProfileIdentifier() & 0xFF);
	    channel.write(Tools.shrink(256, wrap(data.getPublicKey().getModulus().toByteArray())));
	    channel.write(Tools.expand(4, wrap(data.getPublicKey().getPublicExponent().toByteArray())));
	    channel.write(taId());
	    channel.write(data.chr());
	    channel.write(data.car());

	    return wrap(tbs.toByteArray());
	}

	@Override
	public void validate(G1CertificateData data) {
	    if (data.car().remaining() != 8) {
		throw new IllegalArgumentException("CAR must be 8 byte");
	    }
	    if (data.chr().remaining() != 8) {
		throw new IllegalArgumentException("CHR must be 8 byte");
	    }
	    if (data.cha() != null) {
		throw new IllegalArgumentException("CHA not used for CA Certificates");
	    }

	    Tools.ensureX509PublicRsaExponent(data.getPublicKey().getPublicExponent());
	}
    };

    private final byte profileIdentifier;
    private final String taId;

    private G1CVCertificateType(byte profileIdentifier, String taId) {
	this.profileIdentifier = profileIdentifier;
	this.taId = taId;
    }

    public byte getProfileIdentifier() {
	return profileIdentifier;
    }

    public static G1CVCertificateType fromProfileIdentifier(byte cpi) {
	for (G1CVCertificateType type : values()) {
	    if (cpi == type.profileIdentifier) {
		return type;
	    }
	}
	throw new IllegalArgumentException("Unknown profile identifier " + cpi);
    }

    ByteBuffer taId() {
	return Tools.encodedObjectIdentifier(taId);
    }

    void validateOid(ByteBuffer data) {
	ByteBuffer oid = taId();
	byte[] encountered = Tools.readFromBuffer(oid.remaining(), data);

	if (!oid.equals(wrap(encountered))) {
	    throw new IllegalStateException("oid mismatch - expected " + taId);
	}
    }
}
