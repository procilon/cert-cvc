package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * A BER TLV structure.
 * 
 * @author fichtelmannm
 *
 */
public class TLV {
    private final Tag tag;
    private final Length length;
    private final Value value;

    /**
     * Create a primitive TLV based on tag length and value. The provided length
     * must match the size of the value.
     * 
     * @param tag
     *            the tag to be used.
     * @param length
     *            the length, must be consistent with the value size
     * @param value
     *            the value
     */
    public TLV(Tag tag, Length length, Value value) {
	assertConsistentLength(length, value);
	this.tag = tag;
	this.length = length;
	this.value = value;
    }

    private void assertConsistentLength(Length length, Value value) {
	if (length.getLength() != value.size()) {
	    throw new IllegalArgumentException("length does not match value length");
	}
    }

    /**
     * Create a TLV using tag and value and a computed length.
     * 
     * @param tag
     *            the tag to be used.
     * @param value
     *            the value
     */
    public TLV(Tag tag, Value value) {
	this(tag, new Length(value.size()), value);
    }

    /**
     * The tag.
     * 
     * @return the tag.
     */
    public Tag getTag() {
	return tag;
    }

    /**
     * The length.
     * 
     * @return the length.
     */
    public Length getLength() {
	return length;
    }

    /**
     * The value.
     * 
     * @return the value.
     */
    public Value getValue() {
	return value;
    }

    /**
     * The encoded size of this TLV structure.
     * 
     * @return the encoded size of this TLV structure.
     */
    public int size() {
	return tag.size() + length.size() + value.size();
    }

    /**
     * Write this TLV data to the provided {@link ByteBuffer}
     * 
     * @param data
     *            the buffer this TLV will be written to.
     */
    public void encodeTo(ByteBuffer data) {
	tag.encodeTo(data);
	length.encodeTo(data);
	data.put(value.bytes());
    }

    /**
     * Parse the given data into a TLV structure. Advances the buffers position
     * after the TLV.
     * 
     * @param data
     *            the data to be parsed
     * @return the parsed TLV.
     */
    public static TLV parse(ByteBuffer data) {
	Tag tag = Tag.parse(data);
	Length length = Length.parse(data);
	ByteBuffer value = data.duplicate();
	value.limit(value.position() + length.getLength());
	data.position(value.limit());

	return new TLV(tag, length, new SimpleValue(value));
    }

    /**
     * Parse all (top-level) TLV structures in the provided data. Used for parsing
     * constructed values.
     * 
     * @param data
     *            the data containing the structures to be parsed.
     * @return a list of the parsed TLVs
     */
    public static List<TLV> parseList(ByteBuffer data) {
	List<TLV> list = new LinkedList<TLV>();
	while (data.hasRemaining()) {
	    TLV tlv = parse(data);
	    list.add(tlv);
	}

	return new ArrayList<TLV>(list);
    }

    /**
     * Parse all (top-level) TLV structures in the provided value. Used for parsing
     * constructed values.
     * 
     * @param value
     *            the value containing the structures to be parsed.
     * @return a list of the parsed TLVs
     */
    public static List<TLV> parseList(Value value) {
	return parseList(value.bytes());
    }
}
