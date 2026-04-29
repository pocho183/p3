package it.technosky.server.p3.protocol;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.springframework.util.StringUtils;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;

final class P3WireSupport {

    static final int TAG_CLASS_UNIVERSAL = 0;
    static final int TAG_CLASS_APPLICATION = 1;
    static final int TAG_CLASS_CONTEXT = 2;

    static final int TAG_UNIVERSAL_INTEGER = 2;
    static final int TAG_UNIVERSAL_SEQUENCE = 16;
    static final int TAG_UNIVERSAL_UTF8STRING = 12;
    static final int TAG_UNIVERSAL_PRINTABLESTRING = 19;
    static final int TAG_UNIVERSAL_IA5STRING = 22;
    static final int TAG_UNIVERSAL_VISIBLESTRING = 26;
    static final int TAG_UNIVERSAL_GENERALSTRING = 27;
    static final int TAG_UNIVERSAL_UNIVERSALSTRING = 28;
    static final int TAG_UNIVERSAL_BMPSTRING = 30;

    private P3WireSupport() {
    }

    static byte[] encodeUtf8ContextField(int tagNumber, String value) {
        byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
        byte[] utf8 = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, TAG_UNIVERSAL_UTF8STRING, 0, bytes.length, bytes)
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, utf8.length, utf8));
    }

    static byte[] encodeContextInteger(int tagNumber, int value) {
        byte[] integer = encodeIntegerUniversal(value);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, integer.length, integer));
    }

    static byte[] encodeIntegerUniversal(int value) {
        if (value == 0) {
            return BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, false, TAG_UNIVERSAL_INTEGER, 0, 1, new byte[] { 0x00 })
            );
        }

        int remaining = value;
        byte[] buf = new byte[4];
        int index = buf.length;
        while (remaining > 0) {
            buf[--index] = (byte) (remaining & 0xFF);
            remaining >>>= 8;
        }

        int len = buf.length - index;
        byte[] bytes = new byte[len];
        System.arraycopy(buf, index, bytes, 0, len);

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, TAG_UNIVERSAL_INTEGER, 0, bytes.length, bytes)
        );
    }

    static int decodeInteger(byte[] value) {
        if (value == null || value.length == 0) {
            return 0;
        }
        int number = 0;
        for (byte b : value) {
            number = (number << 8) | (b & 0xFF);
        }
        return number;
    }

    static List<BerTlv> decodeContextFieldList(byte[] payload) {
        try {
            BerTlv maybeSequence = BerCodec.decodeSingle(payload);
            if (maybeSequence.tagClass() == TAG_CLASS_UNIVERSAL
                && maybeSequence.constructed()
                && maybeSequence.tagNumber() == TAG_UNIVERSAL_SEQUENCE) {
                return BerCodec.decodeAll(maybeSequence.value());
            }
        } catch (RuntimeException ignored) {
        }
        return BerCodec.decodeAll(payload);
    }

    static String decodeBerStringValue(BerTlv tlv) {
        if (tlv == null) {
            return null;
        }

        if (tlv.constructed()) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
                if (nested.size() == 1) {
                    return decodeBerStringValue(nested.get(0));
                }
            } catch (RuntimeException ignored) {
                return null;
            }
        }

        return switch (tlv.tagClass()) {
            case TAG_CLASS_UNIVERSAL -> switch (tlv.tagNumber()) {
                case TAG_UNIVERSAL_UTF8STRING -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
                case TAG_UNIVERSAL_PRINTABLESTRING,
                     TAG_UNIVERSAL_IA5STRING,
                     25,
                     TAG_UNIVERSAL_VISIBLESTRING,
                     TAG_UNIVERSAL_GENERALSTRING ->
                    new String(tlv.value(), StandardCharsets.US_ASCII).trim();
                case 20 -> new String(tlv.value(), StandardCharsets.ISO_8859_1).trim();
                case TAG_UNIVERSAL_UNIVERSALSTRING -> decodeUniversalStringSafe(tlv.value());
                case TAG_UNIVERSAL_BMPSTRING -> decodeBmpStringSafe(tlv.value());
                default -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
            };
            default -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
        };
    }

    static String decodeBmpStringSafe(byte[] value) {
        if ((value.length & 1) != 0) {
            return null;
        }
        return new String(value, StandardCharsets.UTF_16BE).trim();
    }

    static String decodeUniversalStringSafe(byte[] value) {
        if ((value.length & 3) != 0) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length; i += 4) {
            int codePoint = ((value[i] & 0xFF) << 24)
                | ((value[i + 1] & 0xFF) << 16)
                | ((value[i + 2] & 0xFF) << 8)
                | (value[i + 3] & 0xFF);
            builder.appendCodePoint(codePoint);
        }
        return builder.toString().trim();
    }

    public static byte[] concat(byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            return new byte[0];
        }

        int totalLength = 0;
        for (byte[] arr : arrays) {
            if (arr != null) {
                totalLength += arr.length;
            }
        }

        byte[] result = new byte[totalLength];
        int offset = 0;

        for (byte[] arr : arrays) {
            if (arr != null && arr.length > 0) {
                System.arraycopy(arr, 0, result, offset, arr.length);
                offset += arr.length;
            }
        }

        return result;
    }

    static byte[] concat(List<byte[]> arrays) {
        if (arrays == null || arrays.isEmpty()) {
            return new byte[0];
        }
        return concat(arrays.toArray(new byte[0][]));
    }

    static String trimToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    static List<String> collectTextualAtoms(BerTlv tlv) {
        List<String> values = new ArrayList<>();
        collectTextualAtomsRecursive(tlv, values);
        return values;
    }

    private static void collectTextualAtomsRecursive(BerTlv tlv, List<String> values) {
        if (tlv.constructed()) {
            try {
                for (BerTlv nested : BerCodec.decodeAll(tlv.value())) {
                    collectTextualAtomsRecursive(nested, values);
                }
            } catch (RuntimeException ignored) {
            }
            return;
        }

        String decoded = decodeBerStringValue(tlv);
        if (StringUtils.hasText(decoded)) {
            values.add(decoded);
        }
    }
}