package org.ejbca.cvc.internal.tlv;

/**
 * Represention of the 4 BER Tag Class states.
 * 
 * @author fichtelmannm
 *
 */
public enum TagClass {
    /**
     * The type is native to ASN.1
     */
    UNIVERSAL((byte) 0),

    /**
     * The type is only valid for one specific application
     */
    APPLICATION((byte) 0x40),

    /**
     * Meaning of this type depends on the context (such as within a sequence, set
     * or choice)
     */
    CONTEXT_SPECIFIC((byte) 0x80),

    /**
     * Defined in private specifications
     */
    PRIVATE((byte) 0xC0);

    final byte value;

    private TagClass(byte value) {
	this.value = value;
    }

    /**
     * The tagclass binary value encoded in the first 2 bits of a single byte.
     * 
     * @return the tagclass binary value encoded in the first 2 bits of a single
     *         byte.
     */
    public byte getValue() {
	return value;
    }

    /**
     * Extract the tag class from the first tag byte (contained in the first 2 bits)
     * 
     * @param tag
     *            the first tag byte
     * @return the corresponding TagClass. Never <code>null</code>.
     */
    public static TagClass fromTag(byte tag) {
	int masked = tag & 0xC0;
	for (TagClass tagClass : values()) {
	    if (masked == (tagClass.value & 0xFF)) {
		return tagClass;
	    }
	}

	throw new IllegalStateException("should not be possible");
    }
}
