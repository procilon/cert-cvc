package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;

/**
 * The tag portion of a TLV.
 * <p>
 * A tag consists of 3 components:
 * <ul>
 * <li>class: the context in which the tag is defined</li>
 * <li>constructed: whether the value consists of TLVs itself (i.e.
 * SEQUENCE)</li>
 * <li>tagNumber: the tag number itself - values in the range 0-31 inclusive are
 * encoded in the first byte, multi-byte tag encoding is used to encode larger
 * tag numbers</li>
 * </ul>
 * 
 * @author fichtelmannm
 *
 */
public class Tag {
    public static final byte CONSTRUCTED_MASK = 0x20;
    public static final byte TAG_NO_MASK = 0x1F;

    private final int tagNumber;
    private final TagClass tagClass;
    private final boolean constructed;

    /**
     * Create a tag with the provided information.
     * 
     * @param tagNumber
     *            the actual tag number
     * @param tagClass
     *            the tag class
     * @param constructed
     *            if the value inside this tag is constructed (i.e. SEQUENCE/SET)
     */
    public Tag(int tagNumber, TagClass tagClass, boolean constructed) {
	assertMaximumNotExceeded(tagNumber);
	this.tagNumber = tagNumber;
	this.tagClass = tagClass;
	this.constructed = constructed;
    }

    private static void assertMaximumNotExceeded(int tagNumber) {
	if ((tagNumber >> (7 * 4)) > 0) {
	    throw new IllegalArgumentException("tagNumber out of valid range");
	}
    }

    /**
     * The tag number.
     * 
     * @return the tag number.
     */
    public int getTagNumber() {
	return tagNumber;
    }

    /**
     * The tag class.
     * 
     * @return the tag class.
     */
    public TagClass getTagClass() {
	return tagClass;
    }

    /**
     * Whether the constructed bit is set.
     * 
     * @return <code>true</code> if the constructed bit is set.
     */
    public boolean isConstructed() {
	return constructed;
    }

    /**
     * Calculate the size that is needed to encode this tag.
     * 
     * @return the number of bytes needed to encode this tag.
     */
    public int size() {
	if (tagNumber < 0x1F)
	    return 1;
	else if (tagNumber < 0x80)
	    return 2;
	else if (tagNumber < 0x4000)
	    return 3;
	else if (tagNumber < 0x200000)
	    return 4;
	else
	    return 5;
    }

    /**
     * Encode this tag unto the provided {@link ByteBuffer} starting at the current
     * position and advancing the position by {@link #size()}.
     * 
     * @param data
     *            the {@link ByteBuffer} to write this tag to.
     */
    public void encodeTo(ByteBuffer data) {
	byte first = tagClass.getValue();
	if (constructed) {
	    first |= CONSTRUCTED_MASK;
	}

	if (tagNumber < 31) {
	    first |= tagNumber;
	    data.put(first);
	} else {
	    first |= TAG_NO_MASK;
	    data.put(first);
	    if (tagNumber <= 0x7F) {
		data.put((byte) (tagNumber & 0x7F));
	    } else {
		putMultiByteTag(data, tagNumber);
	    }
	}

    }

    /**
     * Parse a tag from the provided {@link ByteBuffer}. Starts at the current
     * position and advances the position after the last tag byte.
     * 
     * @param data
     *            the {@link ByteBuffer} to read from.
     * @return the parsed tag.
     */
    public static Tag parse(ByteBuffer data) {
	byte first = data.get();
	TagClass tagClass = TagClass.fromTag(first);
	boolean constructed = (first & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;

	int tagNo = first & TAG_NO_MASK;
	if (tagNo == TAG_NO_MASK) {
	    tagNo = parseMultiByteTag(data);
	}

	return new Tag(tagNo, tagClass, constructed);
    }

    @Override
    public String toString() {
	return String.format("Tag(no=%d,class=%s,constructed=%b)", tagNumber, tagClass, constructed);
    }

    private static void putMultiByteTag(ByteBuffer data, int tagNumber) {
	byte[] stack = new byte[5];
	int position = stack.length;

	stack[--position] = (byte) (tagNumber & 0x7F);
	do {
	    tagNumber >>= 7;
	    stack[--position] = (byte) (tagNumber & 0x7F);
	} while (tagNumber > 0x7F);

	data.put(stack, position, stack.length - position);
    }

    private static int parseMultiByteTag(ByteBuffer data) {
	int tagNo = 0;
	byte b;
	int processed = 0;

	do {
	    tagNo <<= 7;
	    b = data.get();
	    tagNo |= b & 0x7F;
	    processed++;
	} while ((b & 0x80) != 0 && processed < 4);
	if ((b & 0x80) != 0 && processed == 4) {
	    throw new IllegalStateException("illegal tag length (>5 bytes)");
	}

	return tagNo;
    }
}
