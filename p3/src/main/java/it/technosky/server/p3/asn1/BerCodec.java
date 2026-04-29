package it.technosky.server.p3.asn1;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class BerCodec {

    public static final int TAG_CLASS_UNIVERSAL = 0;
    public static final int TAG_CLASS_APPLICATION = 1;
    public static final int TAG_CLASS_CONTEXT = 2;

    private BerCodec() {
    }

    public static List<BerTlv> decodeAll(byte[] payload) {
        List<BerTlv> result = new ArrayList<>();
        int offset = 0;
        while (offset < payload.length) {
            BerDecodeResult decoded = decodeAt(payload, offset);
            result.add(decoded.tlv());
            offset += decoded.totalLength();
        }
        return result;
    }

    public static BerTlv decodeSingle(byte[] payload) {
        if (payload == null || payload.length == 0)
            throw new IllegalArgumentException("Empty ASN.1 BER payload");
        return decodeAt(payload, 0).tlv();
    }

    public static byte[] encode(BerTlv tlv) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeTag(out, tlv.tagClass(), tlv.constructed(), tlv.tagNumber());
        writeLength(out, tlv.length());
        out.writeBytes(tlv.value());
        return out.toByteArray();
    }

    public static byte[] encodeAll(List<BerTlv> values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (BerTlv tlv : values) {
            out.writeBytes(encode(tlv));
        }
        return out.toByteArray();
    }

    public static Optional<BerTlv> findOptional(List<BerTlv> values, int tagClass, int tagNumber) {
        return values.stream()
            .filter(v -> v.tagClass() == tagClass && v.tagNumber() == tagNumber)
            .findFirst();
    }

    public static BerTlv choose(List<BerTlv> values, int... tagNumbers) {
        for (int tagNumber : tagNumbers) {
            for (BerTlv value : values) {
                if (value.tagNumber() == tagNumber) {
                    return value;
                }
            }
        }
        throw new IllegalArgumentException("No CHOICE arm found for tags " + java.util.Arrays.toString(tagNumbers));
    }

    private static BerDecodeResult decodeAt(byte[] payload, int offset) {
        if (offset >= payload.length) {
            throw new IllegalArgumentException("Missing ASN.1 BER tag");
        }

        int index = offset;
        int firstTagOctet = payload[index++] & 0xFF;
        int tagClass = (firstTagOctet >> 6) & 0x03;
        boolean constructed = (firstTagOctet & 0x20) != 0;
        int tagNumber = firstTagOctet & 0x1F;
        if (tagNumber == 0x1F) {
            tagNumber = 0;
            boolean sawAtLeastOne = false;
            while (true) {
                if (index >= payload.length) {
                    throw new IllegalArgumentException("Truncated high-tag-number form");
                }
                int octet = payload[index++] & 0xFF;
                sawAtLeastOne = true;
                tagNumber = (tagNumber << 7) | (octet & 0x7F);
                if ((octet & 0x80) == 0) {
                    break;
                }
            }
            if (!sawAtLeastOne) {
                throw new IllegalArgumentException("Invalid high-tag-number form");
            }
        }

        if (index >= payload.length) {
            throw new IllegalArgumentException("Missing ASN.1 BER length");
        }

        int firstLengthOctet = payload[index++] & 0xFF;
        int valueLength;
        if ((firstLengthOctet & 0x80) == 0) {
            valueLength = firstLengthOctet;
        } else {
            int numberOfLengthOctets = firstLengthOctet & 0x7F;
            if (numberOfLengthOctets == 0) {
                throw new IllegalArgumentException("Indefinite BER length is not supported");
            }
            if (numberOfLengthOctets > 4) {
                throw new IllegalArgumentException("BER length too large");
            }
            if (index + numberOfLengthOctets > payload.length) {
                throw new IllegalArgumentException("Truncated BER length");
            }
            valueLength = 0;
            for (int i = 0; i < numberOfLengthOctets; i++) {
                valueLength = (valueLength << 8) | (payload[index++] & 0xFF);
            }
        }

        if (valueLength < 0 || index + valueLength > payload.length) {
            throw new IllegalArgumentException("BER value length exceeds available bytes");
        }

        byte[] value = java.util.Arrays.copyOfRange(payload, index, index + valueLength);
        int headerLength = index - offset;
        int totalLength = headerLength + valueLength;
        return new BerDecodeResult(new BerTlv(tagClass, constructed, tagNumber, headerLength, valueLength, value), totalLength);
    }

    private static void writeTag(ByteArrayOutputStream out, int tagClass, boolean constructed, int tagNumber) {
        int firstOctet = (tagClass & 0x03) << 6;
        if (constructed) {
            firstOctet |= 0x20;
        }
        if (tagNumber < 31) {
            out.write(firstOctet | tagNumber);
            return;
        }

        out.write(firstOctet | 0x1F);
        int[] chunks = new int[6];
        int chunkCount = 0;
        int number = tagNumber;
        do {
            chunks[chunkCount++] = number & 0x7F;
            number >>= 7;
        } while (number > 0);

        for (int i = chunkCount - 1; i >= 0; i--) {
            int octet = chunks[i];
            if (i != 0) {
                octet |= 0x80;
            }
            out.write(octet);
        }
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
            return;
        }

        int temp = length;
        int bytes = 0;
        byte[] lengthBuffer = new byte[4];
        while (temp > 0) {
            lengthBuffer[bytes++] = (byte) (temp & 0xFF);
            temp >>= 8;
        }
        out.write(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write(lengthBuffer[i]);
        }
    }

    private record BerDecodeResult(BerTlv tlv, int totalLength) {
    }
}
