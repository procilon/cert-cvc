package org.ejbca.cvc.ghc;

import static java.nio.ByteBuffer.wrap;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.cvc.internal.tlv.TLV;

/**
 * The eGK G1 CVC holds an RSA 2048 public key and is signed using RSA 2048.
 * <p>
 * Instead of using common signature schemes (RSA PKCS1_v1.5 or RSA_SSA_PSS),
 * part of the signed data is embedded into the signature itself.
 * <p>
 * This makes it possible to have an RSA 2048 signed certificate for a RSA 2048
 * key within less than 350 byte - reducing the certificate size by 222 bytes, a
 * significant amount on a smartcard chip.
 * 
 * @author fichtelmannm
 *
 */
public class G1Sample {
    static {
	Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	generator.initialize(2048);
	KeyPair keyPair = generator.generateKeyPair();
	RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
	RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

	System.out.println("modulus: " + Hex.toHexString(publicKey.getModulus().toByteArray()));
	System.out.println("public exponent: " + Hex.toHexString(publicKey.getPublicExponent().toByteArray()));

	G1RsaCVCCA ca = new G1RsaCVCCA();

	byte[] rootCR = "DEYYR001".getBytes();
	byte[] intermediateCR = "DEYYI001".getBytes();
	byte[] eeCR = "DEYYE-000001".getBytes();
	TLV root = ca.issue(G1CVCertificateType.CA_CERTIFICATE,
		new G1CertificateData(publicKey, wrap(rootCR), wrap(rootCR)), privateKey, privateKey.getModulus());

	System.out.println(root);

	ByteBuffer out = ByteBuffer.allocate(root.size());
	root.encodeTo(out);

	System.out.println(Hex.toHexString(out.array()));

	TLV intermediate = ca.issue(G1CVCertificateType.CA_CERTIFICATE,
		new G1CertificateData(publicKey, wrap(rootCR), wrap(intermediateCR)), privateKey,
		privateKey.getModulus());

	System.out.println(intermediate);

	out = ByteBuffer.allocate(intermediate.size());
	intermediate.encodeTo(out);

	System.out.println(Hex.toHexString(out.array()));

	TLV authCert = ca.issue(G1CVCertificateType.AUTHENTICATION_CERTIFICATE,
		new G1CertificateData(publicKey, wrap(intermediateCR), wrap(eeCR), wrap("1234567".getBytes())),
		privateKey, privateKey.getModulus());

	System.out.println(authCert);

	out = ByteBuffer.allocate(authCert.size());
	authCert.encodeTo(out);

	System.out.println(Hex.toHexString(out.array()));
    }
}
