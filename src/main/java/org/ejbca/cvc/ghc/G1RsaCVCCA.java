package org.ejbca.cvc.ghc;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.internal.tlv.ConstructedValue;
import org.ejbca.cvc.internal.tlv.SimpleValue;
import org.ejbca.cvc.internal.tlv.TLV;
import org.ejbca.cvc.internal.tlv.Tag;
import org.ejbca.cvc.internal.tlv.TagClass;
import org.ejbca.cvc.jca.JceRsaKeyParameter;
import org.ejbca.cvc.jca.JceTextbookRSA;

/**
 * CA for G1 CVC certificates with RSA keys.
 * 
 * @author fichtelmannm
 *
 */
public class G1RsaCVCCA {

    public static final Tag CV_CERTIFICATE = new Tag(33, TagClass.APPLICATION, true);
    public static final Tag CV_SIGNATURE = new Tag(55, TagClass.APPLICATION, false);
    public static final Tag CV_TRAILING = new Tag(56, TagClass.APPLICATION, false);

    /**
     * 
     * @param generator
     * @param data
     * @param issuerKey
     * @param issuerModulus
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     * @throws CryptoException
     */
    public TLV issue(G1CertificateGenerator generator, G1CertificateData data, PrivateKey issuerKey,
	    BigInteger issuerModulus) throws IOException, GeneralSecurityException, CryptoException {

	ByteBuffer tbsBuf = generator.generate(data);
	byte[] tbs = new byte[tbsBuf.remaining()];
	tbsBuf.get(tbs);

	ISO9796d2Signer signer = new ISO9796d2Signer(new JceTextbookRSA(BouncyCastleProvider.PROVIDER_NAME),
		new SHA256Digest(), true);
	CipherParameters params = new JceRsaKeyParameter(true, issuerKey, issuerModulus);

	signer.init(true, params);

	signer.update(tbs, 0, tbs.length);

	byte[] signature = signer.generateSignature();

	byte[] innerMsg = signer.getRecoveredMessage();
	byte[] trailing = new byte[tbs.length - innerMsg.length];
	System.arraycopy(tbs, innerMsg.length, trailing, 0, trailing.length);

	return new TLV(CV_CERTIFICATE, new ConstructedValue( //
		new TLV(CV_SIGNATURE, new SimpleValue(ByteBuffer.wrap(signature))), //
		new TLV(CV_TRAILING, new SimpleValue(ByteBuffer.wrap(trailing)))) //
	);

    }
}
