package org.ejbca.cvc.ghc;

import java.nio.ByteBuffer;

public interface G1CertificateDataParser {
    G1CertificateData parse(ByteBuffer data);
}
