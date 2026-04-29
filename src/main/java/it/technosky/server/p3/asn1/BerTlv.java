package it.technosky.server.p3.asn1;

public record BerTlv(int tagClass, boolean constructed, int tagNumber, int headerLength, int length, byte[] value) {

    public BerTlv {
        if (tagClass < 0 || tagClass > 3) {
            throw new IllegalArgumentException("Invalid ASN.1 tag class: " + tagClass);
        }
        if (tagNumber < 0) {
            throw new IllegalArgumentException("Invalid ASN.1 tag number: " + tagNumber);
        }
        if (length < 0) {
            throw new IllegalArgumentException("Invalid ASN.1 length: " + length);
        }
        if (value == null || value.length != length) {
            throw new IllegalArgumentException("ASN.1 value length mismatch");
        }
    }

    public boolean isUniversal() {
        return tagClass == 0;
    }

    public boolean isContextSpecific() {
        return tagClass == 2;
    }
}
