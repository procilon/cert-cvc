package org.ejbca.cvc.internal.tlv;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * A constructed {@link Value}. A constructed value does not have a value itself
 * but contains other TLVs.
 * 
 * @author fichtelmannm
 *
 */
public class ConstructedValue implements Value {
    private final List<TLV> sequence;

    /**
     * Construct an empty constructed value.
     */
    public ConstructedValue() {
	this.sequence = new ArrayList<TLV>();
    }

    /**
     * Construct a constructed value with the specified entries.
     * 
     * @param entries
     *            a sequence of entries
     */
    public ConstructedValue(TLV... entries) {
	this(Arrays.asList(entries));
    }

    /**
     * Construct a constructed value with the specified entries.
     * 
     * @param entries
     *            a sequence of entries
     */
    public ConstructedValue(Iterable<? extends TLV> entries) {
	this();
	for (TLV entry : entries) {
	    sequence.add(entry);
	}
    }

    /**
     * Add a tlv at the end of this list.
     * 
     * @param e
     *            the tlv structure to be added.
     */
    public void add(TLV e) {
	sequence.add(e);
    }

    /**
     * Add all of the provided tlvs to the end of this list.
     * 
     * @param c
     *            the entries to be added.
     */
    public void addAll(Collection<? extends TLV> c) {
	sequence.addAll(c);
    }

    /**
     * Create an unmodifiable view on the elements of this list.
     * 
     * @return Create an unmodifiable view on the elements of this list.
     */
    public List<TLV> list() {
	return Collections.unmodifiableList(sequence);
    }

    @Override
    public ByteBuffer bytes() {
	ByteBuffer buffer = ByteBuffer.allocate(size());
	for (TLV entry : sequence) {
	    entry.encodeTo(buffer);
	}
	buffer.position(0);
	return buffer;
    }

    @Override
    public byte[] asBytes() {
	return bytes().array();
    }

    @Override
    public int size() {
	int combinedSize = 0;
	for (TLV entry : sequence) {
	    combinedSize += entry.size();
	}
	return combinedSize;
    }

    @Override
    public String toString() {
	// TODO this could be a fancy incremented asn1 viewer - but for now a trivial
	// implementation should suffice
	return "ConstructedValue(" + sequence + ")";
    }
}
