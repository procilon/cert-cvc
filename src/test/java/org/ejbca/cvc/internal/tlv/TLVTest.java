package org.ejbca.cvc.internal.tlv;

import static java.nio.ByteBuffer.wrap;
import static org.bouncycastle.util.encoders.Hex.decode;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Test;

public class TLVTest {

    @Test
    public void parseAsn1Int() throws Exception {
	// UNIVERSAL 2 [1]
	ByteBuffer structure = wrap(decode("02010a"));

	TLV tlv = TLV.parse(structure);

	assertEquals(TagClass.UNIVERSAL, tlv.getTag().getTagClass());
	assertEquals(0x02, tlv.getTag().getTagNumber());

	assertEquals(1, tlv.getLength().getLength());
	assertEquals(1, tlv.getValue().asBytes().length);

	assertEquals(BigInteger.TEN, new BigInteger(tlv.getValue().asBytes()));
    }

    @Test
    public void parseAsn1Null() throws Exception {
	// UNIVERSAL 5 [0]
	ByteBuffer structure = wrap(decode("0500"));

	TLV tlv = TLV.parse(structure);

	assertEquals(TagClass.UNIVERSAL, tlv.getTag().getTagClass());
	assertEquals(0x05, tlv.getTag().getTagNumber());

	assertEquals(0, tlv.getLength().getLength());
	assertEquals(0, tlv.getValue().asBytes().length);
    }

    @Test
    public void parseCvcSignature() throws Exception {
	// APPLICATION 55 [256]
	String hexEncoded = "5F378201001197C716893F75F056FDAC1013982AEE2CA8E5DC850B0A2D63A6704C4A1866052F87B8A7EA74824038B65FEEEC80477195D54D83AC559C501A7A84BBDA79CBC23BC3D40D4C3F99E82AC5DDB3E8FF5539BD706380F9873C40B7ED2CF1617A2F8ECA4DC19F02A12C25A59E300AAF34CD65EF867A7073121849A19DCA722DAC5B853BEF3DCBA82CB78F5A4F065393C7B69A0D3070E3E6F99ADB695B85932F47198F2DAF61431AFAD8843C7E477DC949F25A5FCC64D8ECC10A70542BE9E07313CE9D138764E3079248415CA3D34A0B4C3D02F2EA9FCF449948D6A958A5A7DC32918259EE6C59633DEFC4BC4EFF6D434241CA05149EE3ABD1009ABD5F1D0395BCEC8F";

	TLV tlv = TLV.parse(wrap(decode(hexEncoded)));

	assertEquals(TagClass.APPLICATION, tlv.getTag().getTagClass());
	assertEquals(55, tlv.getTag().getTagNumber());

	assertEquals(256, tlv.getLength().getLength());
	assertEquals(256, tlv.getValue().asBytes().length);
    }

    @Test
    public void parseCvcCertificateG1() throws Exception {
	// APPLICATION 33 [326]
	// - APPLICATION 55 [256]
	// - APPLICATION 56 [62]
	String hexEncoded = "7F218201465F378201001197C716893F75F056FDAC1013982AEE2CA8E5DC850B0A2D63A6704C4A1866052F87B8A7EA74824038B65FEEEC80477195D54D83AC559C501A7A84BBDA79CBC23BC3D40D4C3F99E82AC5DDB3E8FF5539BD706380F9873C40B7ED2CF1617A2F8ECA4DC19F02A12C25A59E300AAF34CD65EF867A7073121849A19DCA722DAC5B853BEF3DCBA82CB78F5A4F065393C7B69A0D3070E3E6F99ADB695B85932F47198F2DAF61431AFAD8843C7E477DC949F25A5FCC64D8ECC10A70542BE9E07313CE9D138764E3079248415CA3D34A0B4C3D02F2EA9FCF449948D6A958A5A7DC32918259EE6C59633DEFC4BC4EFF6D434241CA05149EE3ABD1009ABD5F1D0395BCEC8F5F383E6C51A87443771A3A613550AA9E38640193B74ED5592E9BC5E2CE4A94CA7B25D2A5A36B000100012B24030402020444454458581101174445445858110117";

	TLV tlv = TLV.parse(wrap(decode(hexEncoded)));

	assertEquals(TagClass.APPLICATION, tlv.getTag().getTagClass());
	assertEquals(33, tlv.getTag().getTagNumber());

	List<TLV> sequence = TLV.parseList(tlv.getValue());
	TLV cvcSig = sequence.get(0);

	assertEquals(TagClass.APPLICATION, cvcSig.getTag().getTagClass());
	assertEquals(55, cvcSig.getTag().getTagNumber());

	assertEquals(256, cvcSig.getLength().getLength());
	assertEquals(256, cvcSig.getValue().asBytes().length);

	TLV cvcTrail = sequence.get(1);

	assertEquals(TagClass.APPLICATION, cvcTrail.getTag().getTagClass());
	assertEquals(56, cvcTrail.getTag().getTagNumber());

	assertEquals(62, cvcTrail.getLength().getLength());
	assertEquals(62, cvcTrail.getValue().asBytes().length);
    }

    @Test
    public void createAsn1Integer() throws Exception {
	TLV tlv = new TLV(new Tag(0x02, TagClass.UNIVERSAL, false), new SimpleValue(wrap(decode("0a"))));

	ByteBuffer encoded = ByteBuffer.allocate(tlv.size());
	tlv.encodeTo(encoded);

	assertArrayEquals(decode("02010A"), encoded.array());
    }

    @Test
    public void createAsn1Null() throws Exception {
	TLV tlv = new TLV(new Tag(0x05, TagClass.UNIVERSAL, false), new SimpleValue(wrap(new byte[0])));

	ByteBuffer encoded = ByteBuffer.allocate(tlv.size());
	tlv.encodeTo(encoded);

	assertArrayEquals(decode("0500"), encoded.array());
    }

    @Test
    public void createCvcSignature() throws Exception {
	String signatureValueHex = "1197C716893F75F056FDAC1013982AEE2CA8E5DC850B0A2D63A6704C4A1866052F87B8A7EA74824038B65FEEEC80477195D54D83AC559C501A7A84BBDA79CBC23BC3D40D4C3F99E82AC5DDB3E8FF5539BD706380F9873C40B7ED2CF1617A2F8ECA4DC19F02A12C25A59E300AAF34CD65EF867A7073121849A19DCA722DAC5B853BEF3DCBA82CB78F5A4F065393C7B69A0D3070E3E6F99ADB695B85932F47198F2DAF61431AFAD8843C7E477DC949F25A5FCC64D8ECC10A70542BE9E07313CE9D138764E3079248415CA3D34A0B4C3D02F2EA9FCF449948D6A958A5A7DC32918259EE6C59633DEFC4BC4EFF6D434241CA05149EE3ABD1009ABD5F1D0395BCEC8F";
	String expectedEncodedHex = "5F37820100" + signatureValueHex;

	TLV tlv = new TLV(new Tag(55, TagClass.APPLICATION, false), new SimpleValue(wrap(decode(signatureValueHex))));

	ByteBuffer encoded = ByteBuffer.allocate(tlv.size());
	tlv.encodeTo(encoded);

	assertArrayEquals(decode(expectedEncodedHex), encoded.array());
    }

    @Test
    public void createCvcCertificateG1() throws Exception {
	String signatureValueHex = "1197C716893F75F056FDAC1013982AEE2CA8E5DC850B0A2D63A6704C4A1866052F87B8A7EA74824038B65FEEEC80477195D54D83AC559C501A7A84BBDA79CBC23BC3D40D4C3F99E82AC5DDB3E8FF5539BD706380F9873C40B7ED2CF1617A2F8ECA4DC19F02A12C25A59E300AAF34CD65EF867A7073121849A19DCA722DAC5B853BEF3DCBA82CB78F5A4F065393C7B69A0D3070E3E6F99ADB695B85932F47198F2DAF61431AFAD8843C7E477DC949F25A5FCC64D8ECC10A70542BE9E07313CE9D138764E3079248415CA3D34A0B4C3D02F2EA9FCF449948D6A958A5A7DC32918259EE6C59633DEFC4BC4EFF6D434241CA05149EE3ABD1009ABD5F1D0395BCEC8F";
	String trailValueHex = "6C51A87443771A3A613550AA9E38640193B74ED5592E9BC5E2CE4A94CA7B25D2A5A36B000100012B24030402020444454458581101174445445858110117";
	String expectedCertificateHex = "7F21820146" + "5F37820100" + signatureValueHex + "5F383E" + trailValueHex;

	TLV tlv = new TLV(new Tag(33, TagClass.APPLICATION, true), new ConstructedValue(
		new TLV(new Tag(55, TagClass.APPLICATION, false), new SimpleValue(wrap(decode(signatureValueHex)))),
		new TLV(new Tag(56, TagClass.APPLICATION, false), new SimpleValue(wrap(decode(trailValueHex))))));

	ByteBuffer encoded = ByteBuffer.allocate(tlv.size());
	tlv.encodeTo(encoded);

	assertArrayEquals(decode(expectedCertificateHex), encoded.array());
    }
}
