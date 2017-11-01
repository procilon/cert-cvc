package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;

/**
 * The length portion of a TLV encoding.
 * 
 * @author fichtelmannm
 *
 */
public class Length {
    private final int length;

    /**
     * Construct a length for a content length. The content length must be positive
     * and must not exceed {@link Integer#MAX_VALUE}.
     * 
     * @param length
     *            the content length.
     */
    public Length(int length) {
	assertPositive(length);
	this.length = length;
    }

    private void assertPositive(int length) {
	if (length < 0) {
	    throw new IllegalArgumentException("length MUST be positive");
	}
    }

    /**
     * Retrieve the content length.
     * 
     * @return the content length.
     */
    public int getLength() {
	return length;
    }

    /**
     * Retrieve the number of bytes, this length will be encoded into.
     * 
     * @return the number of bytes, this length will be encoded into.
     */
    public int size() {
	if (length <= 0x7F)
	    return 1;
	else if (length <= 0xFF)
	    return 2;
	else if (length <= 0xFFFF)
	    return 3;
	else if (length <= 0xFFFFFF)
	    return 4;
	else
	    return 5;
    }

    /**
     * Encode this length onto the provided {@link ByteBuffer}.
     * 
     * @param target
     *            the {@link ByteBuffer} to write the length bytes to
     */
    public void encodeTo(ByteBuffer target) {
	if (length <= 0x7F) {
	    target.put((byte) length);
	    return;
	} else {
	    int size = size() - 1;
	    target.put((byte) (size | 0x80));

	    for (int i = size - 1; i >= 0; i--) {
		byte b = (byte) (length >> (i * 8) & 0xFF);
		target.put(b);
	    }
	}
    }

    /**
     * Parse a TLV length field from the provided {@link ByteBuffer}. Advances the
     * position by the number of bytes the length is encoded into.
     * 
     * @param data
     *            the {@link ByteBuffer} positioned at a length portion.
     * @return the parsed {@link Length}.
     */
    public static Length parse(ByteBuffer data) {
	byte first = data.get();

	if ((first & 0xFF) == 0x80) {
	    throw new UnsupportedOperationException("Indefinite length not supported");
	} else if ((first & 0xFF) < 0x80) {
	    return new Length(first & 0xFF);
	} else {
	    int numBytes = first & 0x7F;
	    int length = parseMultiByteLength(numBytes, data);

	    return new Length(length);
	}
    }

    @Override
    public String toString() {
	return "Length(" + length + ")";
    }

    private static int parseMultiByteLength(int numBytes, ByteBuffer data) {
	switch (numBytes) {
	case 1:
	    return data.get() & 0xFF;
	case 2:
	    return data.getShort() & 0xFFFF;
	case 4: {
	    int length = data.getInt();
	    if (length < 0) {
		throw new IllegalArgumentException("length out of range: 0-" + Integer.MAX_VALUE);
	    }
	    return length;
	}
	case 3: {
	    int length = 0;
	    for (int i = 0; i < 3; i++) {
		length <<= 8;
		length |= data.get() & 0xFF;
	    }
	    return length;
	}
	default:
	    throw new IllegalArgumentException("length encoded in more than 4 bytes exceeds maximum length");
	}
    }
}
