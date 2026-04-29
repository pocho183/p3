package it.technosky.server.p3.address;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;

public final class ORNameMapper {

    private static final Map<String, String> DIRECTORY_TYPE_OID_MAP = createDirectoryTypeOidMap();

    private ORNameMapper() {
    }

    public record ORName(Optional<String> directoryName, ORAddress orAddress) {
    }

    public static ORName fromLegacyIa5(String ia5OrAddress) {
        ORAddress parsed = ORAddress.parse(ia5OrAddress);
        return new ORName(Optional.empty(), parsed);
    }

    public static ORName fromAttributes(Map<String, String> attributes, String directoryName) {
        return new ORName(Optional.ofNullable(directoryName), ORAddress.of(new LinkedHashMap<>(attributes)));
    }

    public static ORName fromBer(BerTlv originator) {
        if (originator == null) {
            throw new IllegalArgumentException("ORName cannot be null");
        }

        if (!originator.constructed()) {
            return fromLegacyIa5(new String(originator.value(), StandardCharsets.US_ASCII));
        }

        List<BerTlv> fields = extractOrNameFields(originator);
        Optional<String> directoryName = Optional.empty();
        Map<String, String> attributes = new LinkedHashMap<>();

        for (BerTlv field : fields) {
            if (field.tagClass() == 2 && field.tagNumber() == 0) {
                try {
                    directoryName = Optional.of(decodeDirectoryName(field));
                } catch (RuntimeException ignored) {
                    // keep searching
                }
                continue;
            }

            if (field.tagClass() == 2 && field.tagNumber() == 1) {
                tryDecodeOrAddressField(field, attributes);
                if (!attributes.isEmpty()) {
                    break;
                }
            }
        }

        if (attributes.isEmpty()) {
            throw new IllegalArgumentException("Structured ORName missing decodable O/R address");
        }

        if (!looksLikeRealOrAddress(attributes)) {
            throw new IllegalArgumentException("Structured ORName produced incomplete or invalid O/R address");
        }

        return new ORName(directoryName, ORAddress.of(attributes));
    }

    private static List<BerTlv> extractOrNameFields(BerTlv originator) {
        if (originator == null || !originator.constructed()) {
            return List.of();
        }

        try {
            List<BerTlv> direct = BerCodec.decodeAll(originator.value());
            if (direct.size() == 1) {
                BerTlv only = direct.get(0);
                if (only.constructed() && only.isUniversal() && only.tagNumber() == 16) {
                    try {
                        return BerCodec.decodeAll(only.value());
                    } catch (RuntimeException ignored) {
                        // fall through
                    }
                }
            }
            return direct;
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static void tryDecodeOrAddressField(BerTlv field, Map<String, String> attributes) {
        if (field == null || !field.constructed()) {
            return;
        }

        // Common case: context[1] wrapping one inner constructed address node.
        try {
            List<BerTlv> children = BerCodec.decodeAll(field.value());
            if (children.size() == 1 && children.get(0).constructed()) {
                decodeStructuredAddress(children.get(0), attributes);
                if (!attributes.isEmpty()) {
                    return;
                }
            }
        } catch (RuntimeException ignored) {
            // continue
        }

        // Fallback: some encodings place the address components directly inside context[1].
        decodeStructuredAddress(field, attributes);
    }

    private static String decodeDirectoryName(BerTlv field) {
        if (!field.constructed()) {
            return decodeString(field);
        }

        List<BerTlv> roots = BerCodec.decodeAll(field.value());
        List<String> canonical = decodeDirectoryDistinguishedName(roots);
        if (!canonical.isEmpty()) {
            return String.join(",", canonical);
        }

        List<String> values = new ArrayList<>();
        collectDirectoryValues(roots, values);
        if (values.isEmpty()) {
            throw new IllegalArgumentException("DirectoryName does not contain decodable attributes");
        }
        return String.join(",", values);
    }

    private static List<String> decodeDirectoryDistinguishedName(List<BerTlv> roots) {
        List<String> values = new ArrayList<>();
        for (BerTlv root : roots) {
            if (!root.constructed() || !root.isUniversal() || root.tagNumber() != 16) {
                continue;
            }
            for (BerTlv rdnSet : BerCodec.decodeAll(root.value())) {
                if (!rdnSet.constructed() || !rdnSet.isUniversal() || rdnSet.tagNumber() != 17) {
                    continue;
                }
                for (BerTlv atv : BerCodec.decodeAll(rdnSet.value())) {
                    if (!atv.constructed() || !atv.isUniversal() || atv.tagNumber() != 16) {
                        continue;
                    }
                    List<BerTlv> pair = BerCodec.decodeAll(atv.value());
                    if (pair.size() < 2 || !pair.get(0).isUniversal() || pair.get(0).tagNumber() != 6) {
                        continue;
                    }
                    String oid = decodeOid(pair.get(0).value());
                    String type = DIRECTORY_TYPE_OID_MAP.getOrDefault(oid, "OID." + oid);
                    String value = decodeString(pair.get(1));
                    values.add(type + "=" + value);
                }
            }
        }
        return values;
    }

    private static void collectDirectoryValues(List<BerTlv> nodes, List<String> values) {
        for (BerTlv node : nodes) {
            if (node.constructed()) {
                collectDirectoryValues(BerCodec.decodeAll(node.value()), values);
                continue;
            }
            values.add(decodeString(node));
        }
    }

    private static void decodeStructuredAddress(BerTlv node, Map<String, String> attributes) {
        if (node == null || !node.constructed()) {
            return;
        }

        List<BerTlv> children = BerCodec.decodeAll(node.value());
        for (BerTlv child : children) {
            if (child.tagClass() != 2) {
                continue;
            }

            String key = mapKnownAddressTag(child.tagNumber());
            if (key == null) {
                continue;
            }

            String value = decodeAddressComponentValue(child);
            if (!value.isEmpty()) {
                attributes.putIfAbsent(key, value);
            }
        }
    }

    private static String decodeAddressComponentValue(BerTlv tlv) {
        if (!tlv.constructed()) {
            return decodeString(tlv).trim();
        }

        try {
            List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
            if (nested.size() == 1 && !nested.get(0).constructed()) {
                return decodeString(nested.get(0)).trim();
            }
        } catch (RuntimeException ignored) {
            // continue below
        }

        List<String> values = new ArrayList<>();
        collectPrimitiveStrings(tlv, values);
        return values.stream()
            .filter(s -> !s.isBlank())
            .findFirst()
            .orElse("");
    }

    private static void collectPrimitiveStrings(BerTlv node, List<String> values) {
        if (node == null) {
            return;
        }

        if (!node.constructed()) {
            values.add(decodeString(node));
            return;
        }

        try {
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                collectPrimitiveStrings(child, values);
            }
        } catch (RuntimeException ignored) {
            // ignore undecodable branch
        }
    }

    private static String mapKnownAddressTag(int tagNumber) {
        return switch (tagNumber) {
            case 0 -> "C";
            case 1 -> "ADMD";
            case 2 -> "PRMD";
            case 3 -> "O";
            case 4 -> "OU1";
            case 5 -> "OU2";
            case 6 -> "OU3";
            case 7 -> "OU4";
            case 8 -> "CN";
            case 9 -> "S";
            case 10 -> "G";
            case 11 -> "I";
            case 12 -> "NUMUID";
            default -> null;
        };
    }

    private static boolean looksLikeRealOrAddress(Map<String, String> attributes) {
        if (attributes.isEmpty()) {
            return false;
        }

        if (attributes.containsKey("CN")) {
            return true;
        }

        if (attributes.containsKey("O") && (attributes.containsKey("PRMD") || attributes.containsKey("ADMD"))) {
            return true;
        }

        return attributes.containsKey("O") && attributes.containsKey("C");
    }

    private static String decodeString(BerTlv tlv) {
        if (tlv.constructed()) {
            List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
            if (nested.size() == 1) {
                return decodeString(nested.get(0));
            }
        }

        if (tlv.tagClass() != 0) {
            return new String(tlv.value(), StandardCharsets.UTF_8);
        }

        return switch (tlv.tagNumber()) {
            case 12 -> new String(tlv.value(), StandardCharsets.UTF_8);
            case 19, 22, 25 -> new String(tlv.value(), StandardCharsets.US_ASCII);
            case 20 -> new String(tlv.value(), StandardCharsets.ISO_8859_1);
            case 30 -> decodeBmpString(tlv.value());
            case 28 -> decodeUniversalString(tlv.value());
            default -> new String(tlv.value(), StandardCharsets.UTF_8);
        };
    }

    private static String decodeBmpString(byte[] value) {
        if ((value.length & 1) != 0) {
            throw new IllegalArgumentException("Invalid BMPString length");
        }
        return new String(value, StandardCharsets.UTF_16BE);
    }

    private static String decodeUniversalString(byte[] value) {
        if ((value.length & 3) != 0) {
            throw new IllegalArgumentException("Invalid UniversalString length");
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length; i += 4) {
            int codePoint = ((value[i] & 0xFF) << 24)
                | ((value[i + 1] & 0xFF) << 16)
                | ((value[i + 2] & 0xFF) << 8)
                | (value[i + 3] & 0xFF);
            builder.appendCodePoint(codePoint);
        }
        return builder.toString();
    }

    private static Map<String, String> createDirectoryTypeOidMap() {
        Map<String, String> map = new HashMap<>();
        map.put("2.5.4.3", "CN");
        map.put("2.5.4.6", "C");
        map.put("2.5.4.10", "O");
        map.put("2.5.4.11", "OU");
        map.put("2.5.4.7", "L");
        map.put("2.5.4.8", "ST");
        map.put("2.5.4.9", "STREET");
        return map;
    }

    private static String decodeOid(byte[] encoded) {
        if (encoded.length == 0) {
            throw new IllegalArgumentException("OID cannot be empty");
        }

        List<Long> components = new ArrayList<>();
        int first = encoded[0] & 0xFF;
        components.add((long) (first / 40));
        components.add((long) (first % 40));

        long value = 0;
        for (int i = 1; i < encoded.length; i++) {
            int b = encoded[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                components.add(value);
                value = 0;
            }
        }
        if ((encoded[encoded.length - 1] & 0x80) != 0) {
            throw new IllegalArgumentException("Invalid OID encoding");
        }

        StringBuilder dotted = new StringBuilder();
        for (long component : components) {
            if (dotted.length() > 0) {
                dotted.append('.');
            }
            dotted.append(component);
        }
        return dotted.toString();
    }
}