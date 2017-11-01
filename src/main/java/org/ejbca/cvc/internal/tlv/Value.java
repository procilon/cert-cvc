package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public interface Value {

    /**
     * Get access to a duplicate of the underlying {@link ByteBuffer}.
     * 
     * @return a duplicate of the underlying {@link ByteBuffer}.
     * @see ByteBuffer#duplicate()
     */
    ByteBuffer bytes();

    /**
     * Decodes this value with the provided charset.
     * 
     * @param charset
     *            the charset to decode the value.
     * @return the string representation of this value.
     */
    String asString(Charset charset);

    /**
     * Decodes this value as ascii string.
     * 
     * @return the string representation of this value.
     */
    String asString();

    /**
     * Copies the content of this value into a new byte array.
     * 
     * @return a bytearray with the content of this value.
     */
    byte[] asBytes();

    /**
     * Returns the length of this value.
     * 
     * @return the length of this value.
     */
    int size();

}