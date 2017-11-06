package org.ejbca.cvc.ghc;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface G1CertificateGenerator {
    ByteBuffer generate(G1CertificateData data) throws IOException;
}
