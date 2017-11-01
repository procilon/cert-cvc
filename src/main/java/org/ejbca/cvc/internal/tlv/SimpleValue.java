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

    @Override
    public ByteBuffer bytes() {
	return bytes.duplicate();
    }

    /**
     * Decodes this value with the provided charset.
     * 
     * @param charset
     *            the charset to decode the value.
     * @return the string representation of this value.
     */
    public String asString(Charset charset) {
	CharBuffer result = charset.decode(bytes);
	bytes.reset();
	return result.toString();
    }

    /**
     * Decodes this value as ascii string.
     * 
     * @return the string representation of this value.
     */
    public String asString() {
	return asString(StandardCharsets.US_ASCII);
    }

    @Override
    public byte[] asBytes() {
	byte[] binaryValue = new byte[bytes.remaining()];
	bytes.get(binaryValue);
	bytes.reset();
	return binaryValue;
    }

    @Override
    public int size() {
	return bytes.remaining();
    }

    @Override
    public String toString() {
	return "SimpleValue(size=" + size() + ")";
    }
}
