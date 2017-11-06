package org.ejbca.cvc.ghc;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public class G1CertificateData {
    private final RSAPublicKey publicKey;
    private final ByteBuffer car;
    private final ByteBuffer chr;
    private final ByteBuffer cha;

    public G1CertificateData(RSAPublicKey publicKey, ByteBuffer car, ByteBuffer chr, ByteBuffer cha) {
	Objects.requireNonNull(publicKey, "missing publicKey");
	Objects.requireNonNull(car, "missing CAR");
	Objects.requireNonNull(chr, "missing CHR");

	this.publicKey = publicKey;
	this.car = car.asReadOnlyBuffer();
	this.chr = chr.asReadOnlyBuffer();
	this.cha = cha == null ? null : cha.asReadOnlyBuffer();
    }

    public G1CertificateData(RSAPublicKey publicKey, ByteBuffer car, ByteBuffer chr) {
	this(publicKey, car, chr, null);
    }

    public RSAPublicKey getPublicKey() {
	return publicKey;
    }

    public ByteBuffer car() {
	return car.duplicate();
    }

    public ByteBuffer chr() {
	return chr.duplicate();
    }

    public ByteBuffer cha() {
	return cha == null ? null : cha.duplicate();
    }

    @Override
    public String toString() {
	return "G1CertificateData [publicKey=" + publicKey + ", car=" + car + ", chr=" + chr + ", cha=" + cha + "]";
    }
}
