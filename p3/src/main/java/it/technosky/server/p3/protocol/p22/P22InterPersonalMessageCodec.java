package it.technosky.server.p3.protocol.p22;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.protocol.p22.P22OperationModels.InterPersonalMessageRequest;
import it.technosky.server.p3.protocol.p22.P22OperationModels.InterPersonalMessageResult;

@Component
public class P22InterPersonalMessageCodec {

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    // From your trace the P22 content starts with APPLICATION 1
    private static final int P22_IPM_OUTER_TAG = 1;

    public boolean isLikelyInterPersonalMessage(byte[] encodedArgument) {
        if (encodedArgument == null || encodedArgument.length == 0) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encodedArgument);
            return tlv.tagClass() == TAG_CLASS_APPLICATION
                && tlv.constructed()
                && tlv.tagNumber() == P22_IPM_OUTER_TAG;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public InterPersonalMessageRequest decode(int invokeId, byte[] encodedArgument) {
        if (encodedArgument == null || encodedArgument.length == 0) {
            throw new IllegalArgumentException("Empty P22 IPM argument");
        }

        BerTlv root = BerCodec.decodeSingle(encodedArgument);
        if (root.tagClass() != TAG_CLASS_APPLICATION
            || !root.constructed()
            || root.tagNumber() != P22_IPM_OUTER_TAG) {
            throw new IllegalArgumentException("Not a P22 interpersonal-message argument");
        }

        List<String> texts = new ArrayList<>();
        collectTextualAtoms(root, texts);

        String headingIdentifier = findFirst(texts, t -> t.matches("\\d{10,20}"));
        String subject = findFirst(texts, t -> t.toUpperCase().contains("DATIS"));
        String body = findLongestMultiline(texts);

        return new InterPersonalMessageRequest(
            invokeId,
            Optional.empty(),
            Optional.empty(),
            Optional.ofNullable(trimToNull(headingIdentifier)),
            Optional.ofNullable(trimToNull(subject)),
            Optional.ofNullable(trimToNull(body)),
            encodedArgument
        );
    }

    public byte[] encodeSubmissionResult(InterPersonalMessageResult result) {
        byte[] accepted = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                false,
                0,
                0,
                1,
                new byte[] { 0x00 }
            )
        );

        byte[] message = encodeUtf8ContextField(1, result.deliveryMessage());

        byte[] payload = concat(accepted, message);

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                1,
                0,
                payload.length,
                payload
            )
        );
    }

    private void collectTextualAtoms(BerTlv node, List<String> out) {
        if (node == null) {
            return;
        }

        String decoded = decodeBerStringValue(node);
        if (StringUtils.hasText(decoded)) {
            out.add(decoded);
        }

        if (!node.constructed()) {
            return;
        }

        try {
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                collectTextualAtoms(child, out);
            }
        } catch (RuntimeException ignored) {
        }
    }

    private String decodeBerStringValue(BerTlv tlv) {
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
                case 12 -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
                case 19, 20, 22, 25, 26, 27 -> new String(tlv.value(), StandardCharsets.US_ASCII).trim();
                case 30 -> decodeBmpStringSafe(tlv.value());
                default -> null;
            };
            default -> null;
        };
    }

    private String decodeBmpStringSafe(byte[] value) {
        if (value == null || (value.length & 1) != 0) {
            return null;
        }
        return new String(value, StandardCharsets.UTF_16BE).trim();
    }

    private String findFirst(List<String> values, Predicate<String> predicate) {
        for (String value : values) {
            if (StringUtils.hasText(value) && predicate.test(value)) {
                return value;
            }
        }
        return null;
    }

    private String findLongestMultiline(List<String> values) {
        String best = null;
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            if (value.contains("\n") || value.contains("\r")) {
                if (best == null || value.length() > best.length()) {
                    best = value;
                }
            }
        }

        if (best != null) {
            return best;
        }

        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            if (best == null || value.length() > best.length()) {
                best = value;
            }
        }

        return best;
    }

    private byte[] encodeUtf8ContextField(int tagNumber, String value) {
        byte[] bytes = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);

        byte[] utf8 = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 12, 0, bytes.length, bytes)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, utf8.length, utf8)
        );
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            if (a != null) {
                total += a.length;
            }
        }

        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            if (a != null && a.length > 0) {
                System.arraycopy(a, 0, out, offset, a.length);
                offset += a.length;
            }
        }
        return out;
    }

    private String trimToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}