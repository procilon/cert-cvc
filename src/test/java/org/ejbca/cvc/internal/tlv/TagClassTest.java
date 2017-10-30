package org.ejbca.cvc.internal.tlv;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TagClassTest {

    @Test
    public void universal() throws Exception {
	byte tag = Byte.parseByte("00000001", 2);
	assertEquals(TagClass.fromTag(tag), TagClass.UNIVERSAL);
    }

    @Test
    public void application() throws Exception {
	byte tag = Byte.parseByte("01000001", 2);
	assertEquals(TagClass.fromTag(tag), TagClass.APPLICATION);
    }

    @Test
    public void contextSpecific() throws Exception {
	byte tag = (byte) Short.parseShort("10000001", 2);
	assertEquals(TagClass.fromTag(tag), TagClass.CONTEXT_SPECIFIC);
    }

    @Test
    public void private_() throws Exception {
	byte tag = (byte) Short.parseShort("11000001", 2);
	assertEquals(TagClass.fromTag(tag), TagClass.PRIVATE);
    }
}
