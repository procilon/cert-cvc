package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;

/**
 * The Value in TLV.
 * 
 * @author fichtelmannm
 *
 */
public interface Value {

    /**
     * Get access to a duplicate of the underlying {@link ByteBuffer}.
     * 
     * @return a duplicate of the underlying {@link ByteBuffer}.
     * @see ByteBuffer#duplicate()
     */
    ByteBuffer bytes();

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