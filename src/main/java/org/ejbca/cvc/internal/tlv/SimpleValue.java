package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Simple {@link ByteBuffer} value wrapper.
 * 
 * <p>
 * NOT THREADSAFE - do not use across threads!
 * 
 * @author fichtelmannm
 *
 */
public class SimpleValue implements Value {
    private final ByteBuffer bytes;

    /**
     * Wraps the provided bytes in a value. Intended to use in TLV context.
     * 
     * @param bytes
     *            the bytes of this value.
     */
    public SimpleValue(ByteBuffer bytes) {
	bytes.mark();
	this.bytes = bytes;
    }

    /* (non-Javadoc)
     * @see org.ejbca.cvc.internal.tlv.Value#bytes()
     */
    @Override
    public ByteBuffer bytes() {
	return bytes.duplicate();
    }

    /* (non-Javadoc)
     * @see org.ejbca.cvc.internal.tlv.Value#asString(java.nio.charset.Charset)
     */
    @Override
    public String asString(Charset charset) {
	CharBuffer result = charset.decode(bytes);
	bytes.reset();
	return result.toString();
    }

    /* (non-Javadoc)
     * @see org.ejbca.cvc.internal.tlv.Value#asString()
     */
    @Override
    public String asString() {
	return asString(StandardCharsets.US_ASCII);
    }

    /* (non-Javadoc)
     * @see org.ejbca.cvc.internal.tlv.Value#asBytes()
     */
    @Override
    public byte[] asBytes() {
	byte[] binaryValue = new byte[bytes.remaining()];
	bytes.get(binaryValue);
	bytes.reset();
	return binaryValue;
    }

    /* (non-Javadoc)
     * @see org.ejbca.cvc.internal.tlv.Value#size()
     */
    @Override
    public int size() {
	return bytes.remaining();
    }
}
