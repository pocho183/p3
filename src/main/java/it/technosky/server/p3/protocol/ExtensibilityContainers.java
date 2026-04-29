package it.technosky.server.p3.protocol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;

public final class ExtensibilityContainers {

    private ExtensibilityContainers() {
    }

    public record UnknownExtension(int tagClass, boolean constructed, int tagNumber, byte[] value) {
        public BerTlv toTlv() {
            return new BerTlv(tagClass, constructed, tagNumber, 0, value.length, value);
        }
    }

    public static final class ExtensionContainer {
        private final List<UnknownExtension> unknownExtensions = new ArrayList<>();

        public void add(BerTlv tlv) {
            unknownExtensions.add(new UnknownExtension(tlv.tagClass(), tlv.constructed(), tlv.tagNumber(), tlv.value()));
        }

        public List<UnknownExtension> unknownExtensions() {
            return Collections.unmodifiableList(unknownExtensions);
        }

        public byte[] encodeAll() {
            byte[][] chunks = unknownExtensions.stream().map(x -> BerCodec.encode(x.toTlv())).toArray(byte[][]::new);
            int len = 0;
            for (byte[] c : chunks) {
                len += c.length;
            }
            byte[] out = new byte[len];
            int offset = 0;
            for (byte[] c : chunks) {
                System.arraycopy(c, 0, out, offset, c.length);
                offset += c.length;
            }
            return out;
        }
    }

    public record SecurityParameters(String securityLabel, String token, String algorithmOid) {
        public void validate() {
            if (securityLabel == null || securityLabel.isBlank()) {
                throw new IllegalArgumentException("Security label is required");
            }
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("Security token is required");
            }
            if (algorithmOid == null || algorithmOid.isBlank()) {
                throw new IllegalArgumentException("Security algorithm OID is required");
            }
        }
    }

    @FunctionalInterface
    public interface SecurityValidationHook {
        void validate(SecurityParameters parameters);
    }
}
