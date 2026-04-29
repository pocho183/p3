package it.technosky.server.p3.address;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.util.StringUtils;

public final class ORAddress {

    private static final List<String> CANONICAL_ORDER = List.of("C", "ADMD", "PRMD", "O", "OU1", "OU2", "OU3", "OU4", "CN", "S", "G", "I", "NUMUID");
    private static final Pattern DOMAIN_DEFINED_KEY = Pattern.compile("^DDA-[A-Z0-9][A-Z0-9-]{0,31}$");
    private static final Pattern EXTENSION_KEY = Pattern.compile("^(EXT|X)-[A-Z0-9][A-Z0-9-]{0,31}$");
    private static final Pattern ATTRIBUTE_PATTERN = Pattern.compile("(?:^|[\\s/;,])\\s*([A-Za-z][A-Za-z0-9-]*)\\s*=\\s*(\"(?:[^\"]|\\\\\")*\"|[^/;,]*)");
    private static final Pattern PRINTABLE_STRING = Pattern.compile("^[A-Za-z0-9 '(),\\-.:=?]*$");
    private static final Pattern IA5_STRING = Pattern.compile("^[\\x20-\\x7E]*$");
    private static final List<Character> DISALLOWED_VALUE_CHARS = List.of('/', '+', '"');
    private static final Map<String, Integer> MAX_LENGTHS = Map.ofEntries(
    	Map.entry("C", 3),
        Map.entry("ADMD", 16),
        Map.entry("PRMD", 16),
        Map.entry("O", 64),
        Map.entry("OU1", 32),
        Map.entry("OU2", 32),
        Map.entry("OU3", 32),
        Map.entry("OU4", 32),
        Map.entry("CN", 64),
        Map.entry("S", 40),
        Map.entry("G", 24),
        Map.entry("I", 5),
        Map.entry("NUMUID", 32)
    );

    private final Map<String, String> attributes;

    private ORAddress(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public static ORAddress of(Map<String, String> attrs) {
        Map<String, String> normalized = new LinkedHashMap<>();
        for (String key : CANONICAL_ORDER) {
            String value = attrs.get(key);
            if (hasEffectiveValue(key, value)) {
                normalized.put(key, normalizedValue(key, value));
            }
        }
        attrs.forEach((key, value) -> {
            if (!normalized.containsKey(key) && hasEffectiveValue(key, value)) {
                normalized.put(key, normalizedValue(key, value));
            }
        });
        return new ORAddress(normalized);
    }

    private static boolean hasEffectiveValue(String key, String value) {
        return StringUtils.hasText(value) || ("ADMD".equals(key) && " ".equals(value));
    }

    private static String normalizedValue(String key, String value) {
        if ("ADMD".equals(key) && " ".equals(value)) {
            return " ";
        }
        return value.trim();
    }

    public static ORAddress parse(String address) {
        if (!StringUtils.hasText(address)) {
            throw new IllegalArgumentException("O/R address cannot be empty");
        }

        Map<String, String> values = new LinkedHashMap<>();
        Matcher matcher = ATTRIBUTE_PATTERN.matcher(address.trim());
        while (matcher.find()) {
            String key = normalizeKey(matcher.group(1));
            String value = normalizeValue(key, matcher.group(2));

            if (!StringUtils.hasText(key) || (!StringUtils.hasText(value) && !("ADMD".equals(key) && " ".equals(value)))) {
                continue;
            }
            validateAttribute(key, value);
            if (values.containsKey(key)) {
                throw new IllegalArgumentException("Duplicate O/R attribute: " + key);
            }
            values.put(key, value);
        }

        if (values.isEmpty()) {
            throw new IllegalArgumentException("Invalid O/R address format");
        }
        return ORAddress.of(values);
    }

    public String get(String key) {
        return attributes.get(key);
    }

    public Map<String, String> attributes() {
        return Collections.unmodifiableMap(attributes);
    }

    public List<String> organizationalUnits() {
        List<String> units = new ArrayList<>();
        for (int i = 1; i <= 4; i++) {
            String value = attributes.get("OU" + i);
            if (StringUtils.hasText(value)) {
                units.add(value);
            }
        }
        return units;
    }

    public String toCanonicalString() {
        StringBuilder builder = new StringBuilder();
        for (String key : CANONICAL_ORDER) {
            if (!attributes.containsKey(key)) {
                continue;
            }
            builder.append('/').append(key).append('=').append(attributes.get(key));
        }
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (CANONICAL_ORDER.contains(entry.getKey())) {
                continue;
            }
            builder.append('/').append(entry.getKey()).append('=').append(entry.getValue());
        }
        return builder.toString();
    }

    private static String normalizeValue(String key, String rawValue) {
        if (rawValue == null) {
            return "";
        }
        String trimmed = rawValue.trim();
        String unquoted = unquote(trimmed);
        if ("ADMD".equals(key) && ("\" \"".equals(trimmed) || "\"\"".equals(trimmed) || unquoted.isEmpty())) {
            return " ";
        }
        return unquoted;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1).trim();
        }
        return value;
    }

    private static String normalizeKey(String rawKey) {
        String key = rawKey == null ? "" : rawKey.trim().toUpperCase();
        return switch (key) {
            case "A" -> "ADMD";
            case "P" -> "PRMD";
            case "OU" -> "OU1";
            case "SURNAME" -> "S";
            case "GIVENNAME" -> "G";
            case "INITIALS" -> "I";
            case "NUMERICUSERIDENTIFIER", "NUMERIC-USER-IDENTIFIER" -> "NUMUID";
            default -> key;
        };
    }

    private static void validateAttribute(String key, String rawValue) {
        if (!CANONICAL_ORDER.contains(key)
            && !EXTENSION_KEY.matcher(key).matches()
            && !DOMAIN_DEFINED_KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Unsupported O/R attribute: " + key);
        }

        String value = rawValue == null ? "" : rawValue;
        Integer maxLength = MAX_LENGTHS.get(key);
        int effectiveMaxLength = maxLength == null ? 256 : maxLength;
        if (value.length() > effectiveMaxLength) {
            throw new IllegalArgumentException("O/R attribute " + key + " exceeds max length " + effectiveMaxLength);
        }

        if ("C".equals(key) && !value.matches("^[A-Z]{2}$|^\\d{3}$")) {
            throw new IllegalArgumentException("O/R attribute C must be alpha-2 or numeric-3 country code");
        }

        for (char ch : value.toCharArray()) {
            if (DISALLOWED_VALUE_CHARS.contains(ch)) {
                throw new IllegalArgumentException("O/R attribute " + key + " contains disallowed character: " + ch);
            }
        }

        if (!PRINTABLE_STRING.matcher(value).matches()) {
            throw new IllegalArgumentException("O/R attribute " + key + " must use PrintableString characters");
        }
    }
}
