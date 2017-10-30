package org.ejbca.cvc.internal.tlv;

import static java.nio.ByteBuffer.wrap;
import static org.bouncycastle.util.encoders.Hex.decode;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class LengthTest {

    @Test(expected = UnsupportedOperationException.class)
    public void parseIndefinteLengthNotSupported() throws Exception {
	Length.parse(wrap(decode("80")));
    }

    @Test
    public void parseSingleByteLengthMin() throws Exception {
	Length length = Length.parse(wrap(decode("00")));

	assertEquals(0, length.getLength());
    }

    @Test
    public void parseSingleByteLengthMax() throws Exception {
	Length length = Length.parse(wrap(decode("7F")));

	assertEquals(0x7F, length.getLength());
    }

    @Test
    public void parseTwoByteLengthMin() throws Exception {
	Length length = Length.parse(wrap(decode("8180")));

	assertEquals(0x80, length.getLength());
    }

    @Test
    public void parseTwoByteLengthMax() throws Exception {
	Length length = Length.parse(wrap(decode("81FF")));

	assertEquals(0xFF, length.getLength());
    }

    @Test
    public void parseThreeByteLengthMin() throws Exception {
	Length length = Length.parse(wrap(decode("820100")));

	assertEquals(0x100, length.getLength());
    }

    @Test
    public void parseThreeByteLengthMax() throws Exception {
	Length length = Length.parse(wrap(decode("82FFFF")));

	assertEquals(0xFFFF, length.getLength());
    }

    @Test
    public void parseFourByteLengthMin() throws Exception {
	Length length = Length.parse(wrap(decode("83010000")));

	assertEquals(0x10000, length.getLength());
    }

    @Test
    public void parseFourByteLengthMax() throws Exception {
	Length length = Length.parse(wrap(decode("83FFFFFF")));

	assertEquals(0xFFFFFF, length.getLength());
    }

    @Test
    public void parseFiveByteLengthMin() throws Exception {
	Length length = Length.parse(wrap(decode("8401000000")));

	assertEquals(0x1000000, length.getLength());
    }

    @Test
    public void parseFiveByteLengthMax() throws Exception {
	Length length = Length.parse(wrap(decode("847FFFFFFF")));

	assertEquals(0x7FFFFFFF, length.getLength());
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseFiveByteLengthOverflow() throws Exception {
	Length.parse(wrap(decode("84F0000000")));
    }

    @Test
    public void sizeSingleByteMin() throws Exception {
	Length length = new Length(0);
	assertEquals(1, length.size());
    }

    @Test
    public void sizeSingleByteMax() throws Exception {
	Length length = new Length(0x7F);
	assertEquals(1, length.size());
    }

    @Test
    public void sizeTwoByteMin() throws Exception {
	Length length = new Length(0x80);
	assertEquals(2, length.size());
    }

    @Test
    public void sizeTwoByteMax() throws Exception {
	Length length = new Length(0xFF);
	assertEquals(2, length.size());
    }

    @Test
    public void sizeThreeByteMin() throws Exception {
	Length length = new Length(0x100);
	assertEquals(3, length.size());
    }

    @Test
    public void sizeThreeByteMax() throws Exception {
	Length length = new Length(0xFFFF);
	assertEquals(3, length.size());
    }

    @Test
    public void sizeFourByteMin() throws Exception {
	Length length = new Length(0x10000);
	assertEquals(4, length.size());
    }

    @Test
    public void sizeFourByteMax() throws Exception {
	Length length = new Length(0xFFFFFF);
	assertEquals(4, length.size());
    }

    @Test
    public void sizeFiveByteMin() throws Exception {
	Length length = new Length(0x1000000);
	assertEquals(5, length.size());
    }

    @Test
    public void sizeFiveByteMax() throws Exception {
	Length length = new Length(0x7FFFFFFF);
	assertEquals(5, length.size());
    }

    @Test
    public void encodeSingleByteLengthMin() throws Exception {
	Length length = new Length(0);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("00", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeSingleByteLengthMax() throws Exception {
	Length length = new Length(0x7F);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("7F", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeTwoByteLengthMin() throws Exception {
	Length length = new Length(0x80);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("8180", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeTwoByteLengthMax() throws Exception {
	Length length = new Length(0xFF);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("81FF", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeThreeByteLengthMin() throws Exception {
	Length length = new Length(0x100);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("820100", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeThreeByteLengthMax() throws Exception {
	Length length = new Length(0xFFFF);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("82FFFF", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeFourByteLengthMin() throws Exception {
	Length length = new Length(0x10000);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("83010000", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeFourByteLengthMax() throws Exception {
	Length length = new Length(0xFFFFFF);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("83FFFFFF", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeFiveByteLengthMin() throws Exception {
	Length length = new Length(0x1000000);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("8401000000", Hex.toHexString(target.array()).toUpperCase());
    }

    @Test
    public void encodeFiveByteLengthMax() throws Exception {
	Length length = new Length(0x7FFFFFFF);

	ByteBuffer target = ByteBuffer.allocate(length.size());
	length.encodeTo(target);
	target.position(0);

	assertEquals("847FFFFFFF", Hex.toHexString(target.array()).toUpperCase());
    }
}
