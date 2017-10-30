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
public class Value {
    private final ByteBuffer bytes;

    /**
     * Wraps the provided bytes in a value. Intended to use in TLV context.
     * 
     * @param bytes
     *            the bytes of this value.
     */
    public Value(ByteBuffer bytes) {
	bytes.mark();
	this.bytes = bytes;
    }

    /**
     * Get access to a duplicate of the underlying {@link ByteBuffer}.
     * 
     * @return a duplicate of the underlying {@link ByteBuffer}.
     * @see ByteBuffer#duplicate()
     */
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

    /**
     * Copies the content of this value into a new byte array.
     * 
     * @return a bytearray with the content of this value.
     */
    public byte[] asBytes() {
	byte[] binaryValue = new byte[bytes.remaining()];
	bytes.get(binaryValue);
	bytes.reset();
	return binaryValue;
    }

    /**
     * Returns the length of this value.
     * 
     * @return the length of this value.
     */
    public int length() {
	return bytes.remaining();
    }
}
