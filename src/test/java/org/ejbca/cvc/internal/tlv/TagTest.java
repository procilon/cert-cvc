package org.ejbca.cvc.internal.tlv;

import static java.nio.ByteBuffer.wrap;
import static org.bouncycastle.util.encoders.Hex.decode;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class TagTest {

    @Test
    public void stdTagShouldParse() throws Exception {
	byte[] rawTag = decode("30");

	Tag tag = Tag.parse(wrap(rawTag));

	assertEquals(tag.getTagNumber(), 0x10);
	assertTrue(tag.isConstructed());
	assertEquals(tag.getTagClass(), TagClass.UNIVERSAL);
    }

    @Test
    public void constructedMultiTagShouldParse() throws Exception {
	byte[] rawTag = decode("7F21");

	Tag tag = Tag.parse(wrap(rawTag));

	assertEquals(tag.getTagNumber(), 33);
	assertTrue(tag.isConstructed());
	assertEquals(tag.getTagClass(), TagClass.APPLICATION);
    }

    @Test
    public void multiTagShouldParse() throws Exception {
	byte[] rawTag = decode("5F37");

	Tag tag = Tag.parse(wrap(rawTag));

	assertEquals(tag.getTagNumber(), 55);
	assertFalse(tag.isConstructed());
	assertEquals(tag.getTagClass(), TagClass.APPLICATION);
    }

    @Test(expected = IllegalStateException.class)
    public void multiTagWithManyBytesShouldThrow() throws Exception {
	// MSB set for at least 4 tagnumber bytes
	byte[] rawTag = decode("5F81818181");

	Tag.parse(wrap(rawTag));
    }

    @Test
    public void stdTagShouldSerialize() throws Exception {
	Tag seqTag = new Tag(0x10, TagClass.UNIVERSAL, true);

	ByteBuffer target = ByteBuffer.allocate(1);
	seqTag.encodeTo(target);
	target.position(0);

	assertEquals("30", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void multiTagShouldSerialize() throws Exception {
	Tag cvcSignatureTag = new Tag(55, TagClass.APPLICATION, false);

	ByteBuffer target = ByteBuffer.allocate(2);
	cvcSignatureTag.encodeTo(target);
	target.position(0);

	assertEquals("5F37", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void singleByteTagSize() throws Exception {
	Tag tag = Tag.parse(wrap(decode("30")));

	assertEquals(1, tag.size());
    }

    @Test
    public void twoByteTagSizeMax() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7F7F")));

	assertEquals(2, tag.size());
    }

    @Test
    public void twoByteTagSizeMin() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7F20")));

	assertEquals(2, tag.size());
    }

    @Test
    public void threeByteTagSizeMax() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7FFF7F")));

	assertEquals(3, tag.size());
    }

    @Test
    public void threeByteTagSizeMin() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7F8101")));

	assertEquals(3, tag.size());
    }

    @Test
    public void fourByteTagSizeMax() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7FFFFF7F")));

	assertEquals(4, tag.size());
    }

    @Test
    public void fourByteTagSizeMin() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7F818101")));

	assertEquals(4, tag.size());
    }

    @Test
    public void fiveByteTagSizeMax() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7FFFFFFF7F")));

	assertEquals(5, tag.size());
    }

    @Test
    public void fiveByteTagSizeMin() throws Exception {
	Tag tag = Tag.parse(wrap(decode("7F81818101")));

	assertEquals(5, tag.size());
    }
}
