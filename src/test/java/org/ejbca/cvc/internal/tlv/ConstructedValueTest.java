package org.ejbca.cvc.internal.tlv;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

public class ConstructedValueTest {

    @Test
    public void emptyValueShouldResultInEmptyBytes() throws Exception {
	ConstructedValue value = new ConstructedValue();

	assertArrayEquals(new byte[0], value.asBytes());
    }

    // TODO tests for correct serialization of non-empty values
}
