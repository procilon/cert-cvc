package org.ejbca.cvc.internal.tlv;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class ValueTest {
    @Test
    public void encodeString() throws Exception {
	Charset charset = StandardCharsets.US_ASCII;

	String testString = "Some test text";
	ByteBuffer bytes = charset.encode(testString);

	Value value = new ParsedValue(bytes.asReadOnlyBuffer());

	assertEquals(testString, value.asString());
    }

    @Test
    public void encodeUTF8String() throws Exception {
	Charset charset = StandardCharsets.UTF_8;

	String testString = "(╯°□°)╯︵ ┻━┻";
	ByteBuffer bytes = charset.encode(testString);

	Value value = new ParsedValue(bytes.asReadOnlyBuffer());

	assertEquals(testString, value.asString(charset));
    }

    @Test
    public void encodeBytes() throws Exception {
	byte[] rawValue = Hex.decode("CAFEBABE");

	Value value = new ParsedValue(ByteBuffer.wrap(rawValue));

	assertEquals(Hex.toHexString(rawValue), Hex.toHexString(value.asBytes()));
    }

    @Test
    public void repeatedEncode() throws Exception {
	String testString = "Some test text";
	byte[] testBytes = testString.getBytes(StandardCharsets.US_ASCII);

	Value value = new ParsedValue(ByteBuffer.wrap(testBytes));

	assertEquals(testString, value.asString());
	assertEquals(testString, value.asString());
	assertEquals(Hex.toHexString(testBytes), Hex.toHexString(value.asBytes()));
	assertEquals(Hex.toHexString(testBytes), Hex.toHexString(value.asBytes()));
    }

    @Test
    public void safeAccessToBuffer() throws Exception {
	byte[] rawValue = Hex.decode("CAFEBABE");

	Value value = new ParsedValue(ByteBuffer.wrap(rawValue));
	value.bytes().position(1);

	assertEquals(Hex.toHexString(rawValue), Hex.toHexString(value.asBytes()));
    }
}
