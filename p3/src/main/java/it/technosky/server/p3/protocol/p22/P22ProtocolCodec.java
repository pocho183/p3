package it.technosky.server.p3.protocol.p22;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.protocol.p22.P22OperationModels.InterPersonalMessageRequest;
import it.technosky.server.p3.protocol.p22.P22OperationModels.InterPersonalMessageResult;
import it.technosky.server.p3.protocol.p22.P22OperationModels.P22Error;
import it.technosky.server.p3.protocol.p22.P22OperationModels.RoseInvoke;

@Component
public class P22ProtocolCodec {

    private static final Logger logger = LoggerFactory.getLogger(P22ProtocolCodec.class);

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int TAG_INTEGER = 2;
    private static final int TAG_NULL = 5;
    private static final int TAG_SEQUENCE = 16;

    private static final int OP_INTERPERSONAL_MESSAGE = 3;

    private static final int MAX_CONTROL_APDU_LEN = 64;
    private static final int MIN_REASONABLE_IPM_LEN = 32;

    private final P22RoseCodec roseCodec;
    private final P22InterPersonalMessageCodec interPersonalMessageCodec;

    public P22ProtocolCodec(
        P22RoseCodec roseCodec,
        P22InterPersonalMessageCodec interPersonalMessageCodec
    ) {
        this.roseCodec = roseCodec;
        this.interPersonalMessageCodec = interPersonalMessageCodec;
    }

    public boolean isSupportedApplicationApdu(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            roseCodec.decodeInvoke(encodedApdu);
            return true;
        } catch (RuntimeException ignored) {
        }

        if (looksLikeReleaseOrControlApdu(encodedApdu)) {
            return true;
        }

        try {
            decodeCompatInvoke(encodedApdu);
            return true;
        } catch (RuntimeException ignored) {
        }

        return false;
    }

    public byte[] handle(byte[] encodedApdu) {
        try {
            if (encodedApdu == null || encodedApdu.length == 0) {
                throw new IllegalArgumentException("Empty P22 APDU");
            }

            logger.info(
                "P22 handle received len={} first-bytes={}",
                encodedApdu.length,
                toHexPreview(encodedApdu, 192)
            );

            try {
                RoseInvoke invoke = roseCodec.decodeInvoke(encodedApdu);

                logger.info(
                    "P22 strict ROSE invoke decoded invokeId={} operationCode={} arg-first-bytes={}",
                    invoke.invokeId(),
                    invoke.operationCode(),
                    toHexPreview(invoke.argument(), 128)
                );

                if (invoke.operationCode() == OP_INTERPERSONAL_MESSAGE
                    && looksLikeRealInterPersonalMessageArgument(invoke.argument())) {
                    return handleInterPersonalMessage(invoke);
                }

                if (looksLikeRealInterPersonalMessageArgument(invoke.argument())) {
                    logger.info(
                        "P22 strict invoke compat-accepted as interpersonal-message invokeId={} operationCode={}",
                        invoke.invokeId(),
                        invoke.operationCode()
                    );
                    return handleInterPersonalMessage(invoke);
                }

                logger.warn(
                    "Unsupported strict P22 ROSE invoke operation op={} invokeId={}",
                    invoke.operationCode(),
                    invoke.invokeId()
                );

                return roseCodec.encodeReturnError(
                    new P22Error(
                        invoke.invokeId(),
                        "unsupported-operation",
                        "Unsupported P22 operation",
                        false
                    )
                );
            } catch (RuntimeException strictFailure) {
                logger.info(
                    "P22 strict ROSE decode failed, trying control/compat paths: {}",
                    strictFailure.getMessage()
                );
            }

            if (looksLikeReleaseOrControlApdu(encodedApdu)) {
                logger.info(
                    "P22 control/release-like APDU detected len={} first-bytes={}",
                    encodedApdu.length,
                    toHexPreview(encodedApdu, 128)
                );

                byte[] releaseResult = buildReleaseResultInsideCodec(encodedApdu);
                if (releaseResult != null) {
                    return releaseResult;
                }

                throw new IllegalArgumentException("Recognized P22 control/release APDU but failed to build response");
            }

            try {
                CompatRoseInvoke compat = decodeCompatInvoke(encodedApdu);

                logger.info(
                    "P22 compat invoke decoded invokeId={} operationCode={} arg-first-bytes={}",
                    compat.invokeId(),
                    compat.operationCode().map(String::valueOf).orElse("<unknown>"),
                    toHexPreview(compat.argument(), 128)
                );

                InterPersonalMessageRequest request =
                    interPersonalMessageCodec.decode(compat.invokeId(), compat.argument());

                logger.info(
                    "P22 message invokeId={} headingId={} subject={} body-preview={}",
                    request.invokeId(),
                    request.headingIdentifier().orElse("<empty>"),
                    request.subject().orElse("<empty>"),
                    preview(request.body().orElse(""), 220)
                );

                byte[] resultPayload = interPersonalMessageCodec.encodeSubmissionResult(
                    new InterPersonalMessageResult(
                        request.invokeId(),
                        "P22 message accepted"
                    )
                );

                return roseCodec.encodeReturnResult(request.invokeId(), resultPayload);

            } catch (IllegalArgumentException compatFailure) {
                logger.info(
                    "P22 compat invoke decode failed: {}",
                    compatFailure.getMessage()
                );
            }

            throw new IllegalArgumentException("Unsupported or unrecognized P22 APDU");

        } catch (IllegalArgumentException ex) {
            logger.warn("Malformed/unsupported P22 APDU: {}", ex.getMessage());

            return roseCodec.encodeReturnError(
                new P22Error(
                    1,
                    "malformed-apdu",
                    ex.getMessage(),
                    false
                )
            );
        }
    }

    private byte[] handleInterPersonalMessage(RoseInvoke invoke) {
        InterPersonalMessageRequest request =
            interPersonalMessageCodec.decode(invoke.invokeId(), invoke.argument());

        logger.info(
            "P22 message invokeId={} headingId={} subject={} body-preview={}",
            request.invokeId(),
            request.headingIdentifier().orElse("<empty>"),
            request.subject().orElse("<empty>"),
            preview(request.body().orElse(""), 220)
        );

        byte[] resultPayload = interPersonalMessageCodec.encodeSubmissionResult(
            new InterPersonalMessageResult(
                request.invokeId(),
                "P22 message accepted"
            )
        );

        return roseCodec.encodeReturnResult(request.invokeId(), resultPayload);
    }

    private CompatRoseInvoke decodeCompatInvoke(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            throw new IllegalArgumentException("Empty P22 APDU");
        }

        BerTlv outer;
        try {
            outer = BerCodec.decodeSingle(encodedApdu);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Invalid BER in P22 APDU", ex);
        }

        if (outer.tagClass() != TAG_CLASS_APPLICATION || !outer.constructed()) {
            throw new IllegalArgumentException("P22 APDU is not an application-constructed BER object");
        }

        if (outer.tagNumber() < 1 || outer.tagNumber() > 4) {
            throw new IllegalArgumentException("Unsupported P22 application tag " + outer.tagNumber());
        }

        if (encodedApdu.length <= MAX_CONTROL_APDU_LEN) {
            throw new IllegalArgumentException("Tiny APDU reserved for control/release handling");
        }

        List<BerTlv> outerFields;
        try {
            outerFields = BerCodec.decodeAll(outer.value());
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Unable to decode outer P22 fields", ex);
        }

        Optional<Integer> invokeId = Optional.empty();
        Optional<Integer> operationCode = Optional.empty();
        byte[] argument = null;

        for (BerTlv field : outerFields) {
            if (!invokeId.isPresent()
                && field.tagClass() == TAG_CLASS_UNIVERSAL
                && !field.constructed()
                && field.tagNumber() == TAG_INTEGER) {
                invokeId = Optional.of(decodeSmallInteger(field.value()));
                continue;
            }

            if (field.tagClass() == TAG_CLASS_CONTEXT && field.constructed()) {
                if (!operationCode.isPresent()) {
                    operationCode = extractFirstIntegerDeep(field);
                }

                if (argument == null) {
                    argument = extractRealInterPersonalMessageArgumentFromNode(field).orElse(null);
                }
            }
        }

        if (!invokeId.isPresent()) {
            throw new IllegalArgumentException("P22 compat invoke does not contain invokeId");
        }

        if (argument == null) {
            throw new IllegalArgumentException("P22 compat invoke does not contain a real interpersonal-message argument");
        }

        return new CompatRoseInvoke(invokeId.get(), operationCode, argument);
    }

    private Optional<byte[]> extractRealInterPersonalMessageArgumentFromNode(BerTlv node) {
        if (node == null) {
            return Optional.empty();
        }

        List<byte[]> candidates = new ArrayList<>();
        collectLikelyInterPersonalMessageCandidates(node, candidates);

        byte[] best = null;
        for (byte[] candidate : candidates) {
            if (!looksLikeRealInterPersonalMessageArgument(candidate)) {
                continue;
            }

            if (best == null || candidate.length < best.length) {
                best = candidate;
            }
        }

        return Optional.ofNullable(best);
    }

    private void collectLikelyInterPersonalMessageCandidates(BerTlv node, List<byte[]> out) {
        if (node == null) {
            return;
        }

        try {
            byte[] encoded = BerCodec.encode(node);

            if (encoded.length >= MIN_REASONABLE_IPM_LEN
                && interPersonalMessageCodec.isLikelyInterPersonalMessage(encoded)) {
                out.add(encoded);
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    collectLikelyInterPersonalMessageCandidates(child, out);
                }
            }
        } catch (RuntimeException ignored) {
        }
    }

    private boolean looksLikeRealInterPersonalMessageArgument(byte[] encoded) {
        if (encoded == null || encoded.length < MIN_REASONABLE_IPM_LEN) {
            return false;
        }

        try {
            if (!interPersonalMessageCodec.isLikelyInterPersonalMessage(encoded)) {
                return false;
            }

            InterPersonalMessageRequest decoded = interPersonalMessageCodec.decode(1, encoded);

            boolean hasHeading = decoded.headingIdentifier()
                .map(String::trim)
                .filter(v -> !v.isEmpty())
                .filter(v -> !looksLikeTokenishGarbage(v))
                .isPresent();

            boolean hasSubject = decoded.subject()
                .map(String::trim)
                .filter(v -> !v.isEmpty())
                .filter(v -> !looksLikeTokenishGarbage(v))
                .isPresent();

            boolean hasBody = decoded.body()
                .map(String::trim)
                .filter(v -> v.length() >= 3)
                .filter(v -> !looksLikeTokenishGarbage(v))
                .isPresent();

            return hasHeading || hasSubject || hasBody;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean looksLikeTokenishGarbage(String value) {
        if (value == null) {
            return false;
        }

        String v = value.trim();
        if (v.isEmpty()) {
            return false;
        }

        if (v.matches("[A-Z0-9]{1,12}")) {
            return true;
        }

        if (v.matches("[A-Z]{2,8}(?:/[A-Z0-9]{1,12})*")) {
            return true;
        }

        return false;
    }

    private boolean looksLikeReleaseOrControlApdu(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encodedApdu);

            if (tlv.tagClass() != TAG_CLASS_APPLICATION || !tlv.constructed() || tlv.tagNumber() != 1) {
                return false;
            }

            if (encodedApdu.length > MAX_CONTROL_APDU_LEN) {
                return false;
            }

            List<BerTlv> fields = BerCodec.decodeAll(tlv.value());
            boolean hasInvokeId = false;

            for (BerTlv field : fields) {
                if (field.tagClass() == TAG_CLASS_UNIVERSAL
                    && !field.constructed()
                    && field.tagNumber() == TAG_INTEGER) {
                    hasInvokeId = true;
                }
            }

            return hasInvokeId;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private byte[] buildReleaseResultInsideCodec(byte[] inboundApdu) {
        try {
            int invokeId = extractInvokeIdOrDefault(inboundApdu, 1);

            byte[] invokeIdField = BerCodec.encode(
                new BerTlv(
                    TAG_CLASS_UNIVERSAL,
                    false,
                    TAG_INTEGER,
                    0,
                    1,
                    new byte[] { (byte) invokeId }
                )
            );

            byte[] nullField = BerCodec.encode(
                new BerTlv(
                    TAG_CLASS_UNIVERSAL,
                    false,
                    TAG_NULL,
                    0,
                    0,
                    new byte[0]
                )
            );

            byte[] resultValue = concat(List.of(invokeIdField, nullField));

            byte[] seq = BerCodec.encode(
                new BerTlv(
                    TAG_CLASS_UNIVERSAL,
                    true,
                    TAG_SEQUENCE,
                    0,
                    resultValue.length,
                    resultValue
                )
            );

            byte[] encoded = BerCodec.encode(
                new BerTlv(
                    TAG_CLASS_APPLICATION,
                    true,
                    1,
                    0,
                    seq.length,
                    seq
                )
            );

            logger.info(
                "P22 release/control result encoded invokeId={} first-bytes={}",
                invokeId,
                toHexPreview(encoded, 128)
            );

            return encoded;
        } catch (RuntimeException ex) {
            logger.warn("Failed to build P22 release/control result: {}", ex.getMessage(), ex);
            return null;
        }
    }

    private int extractInvokeIdOrDefault(byte[] apdu, int defaultValue) {
        if (apdu == null || apdu.length == 0) {
            return defaultValue;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(apdu);
            if (!root.constructed()) {
                return defaultValue;
            }

            List<BerTlv> fields = BerCodec.decodeAll(root.value());
            for (BerTlv field : fields) {
                if (field.tagClass() == TAG_CLASS_UNIVERSAL
                    && !field.constructed()
                    && field.tagNumber() == TAG_INTEGER) {
                    return decodeSmallInteger(field.value());
                }
            }
        } catch (RuntimeException ignored) {
        }

        return defaultValue;
    }

    private Optional<Integer> extractFirstIntegerDeep(BerTlv node) {
        if (node == null) {
            return Optional.empty();
        }

        try {
            if (node.tagClass() == TAG_CLASS_UNIVERSAL
                && !node.constructed()
                && node.tagNumber() == TAG_INTEGER) {
                return Optional.of(decodeSmallInteger(node.value()));
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    Optional<Integer> found = extractFirstIntegerDeep(child);
                    if (found.isPresent()) {
                        return found;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return Optional.empty();
    }

    private int decodeSmallInteger(byte[] value) {
        if (value == null || value.length == 0 || value.length > 4) {
            throw new IllegalArgumentException("Invalid INTEGER length");
        }

        int out = 0;
        for (byte b : value) {
            out = (out << 8) | (b & 0xFF);
        }
        return out;
    }

    private byte[] concat(List<byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (parts != null) {
            for (byte[] part : parts) {
                if (part != null && part.length > 0) {
                    out.write(part, 0, part.length);
                }
            }
        }
        return out.toByteArray();
    }

    private String preview(String value, int maxLen) {
        if (value == null) {
            return "<null>";
        }

        value = value.replace("\r", "\\r").replace("\n", "\\n");
        if (value.length() <= maxLen) {
            return value;
        }
        return value.substring(0, maxLen) + "...";
    }

    private String toHexPreview(byte[] bytes, int maxBytes) {
        if (bytes == null) {
            return "<null>";
        }

        int len = Math.min(bytes.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        if (bytes.length > maxBytes) {
            sb.append(" ...");
        }
        return sb.toString();
    }

    private record CompatRoseInvoke(int invokeId, Optional<Integer> operationCode, byte[] argument) {}
}