package it.technosky.server.p3.protocol;

import static it.technosky.server.p3.protocol.P3WireSupport.TAG_CLASS_APPLICATION;
import static it.technosky.server.p3.protocol.P3WireSupport.TAG_CLASS_CONTEXT;
import static it.technosky.server.p3.protocol.P3WireSupport.TAG_CLASS_UNIVERSAL;
import static it.technosky.server.p3.protocol.P3WireSupport.collectTextualAtoms;
import static it.technosky.server.p3.protocol.P3WireSupport.concat;
import static it.technosky.server.p3.protocol.P3WireSupport.decodeContextFieldList;
import static it.technosky.server.p3.protocol.P3WireSupport.encodeUtf8ContextField;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.address.ORAddress;
import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.domain.AFTNPriority;
import it.technosky.server.p3.domain.AMHSPriority;
import it.technosky.server.p3.protocol.P3OperationModels.P3Error;
import it.technosky.server.p3.protocol.P3OperationModels.SubmitRequest;
import it.technosky.server.p3.protocol.P3OperationModels.SubmitResult;

@Component
public class P3SubmitCodec {


    private static final Logger logger = LoggerFactory.getLogger(P3SubmitCodec.class);
	
    private static final int AMHS_PRIORITY_APPLICATION_TAG = 7;
    private static final int SUBMIT_REQUEST_TAG = 2;
    private static final int ERROR_TAG = 8;
    private static final DateTimeFormatter X400_LOCAL_ID_TIME_FORMAT = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter X400_SUBMISSION_TIME_FORMAT = DateTimeFormatter.ofPattern("yyMMddHHmm'Z'").withZone(ZoneOffset.UTC);
    private static final Pattern AFTN_PRIORITY_LINE = Pattern.compile("^(SS|GG|KK|FF|DD)(?:\\s+|$)");
    private static final Pattern AFTN_FILING_TIME_LINE = Pattern.compile("^((?:0[1-9]|[12]\\d|3[01])(?:[01]\\d|2[0-3])[0-5]\\d)(?:\\s+[A-Z]{8})(?:\\s+.*)?$");

    private record AftnHeader(AFTNPriority priority, String filingTime) { }
    
    @Value("${p3.mts.local-id.country}")
    private String localIdCountry;
    @Value("${p3.mts.local-id.city}")
    private String localIdCity;
    @Value("${p3.mts.local-id.node}")
    private String localIdNode;
    @Value("${p3.mts.local-id.sequence}")
    private String localIdSequence;
    
    public boolean isLikelySubmitRequest(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            BerTlv apdu = BerCodec.decodeSingle(encodedApdu);

            if (apdu.tagClass() == TAG_CLASS_CONTEXT
                && apdu.constructed()
                && apdu.tagNumber() == SUBMIT_REQUEST_TAG) {
                return true;
            }

            // Real P3 submit argument inside ROS invoke:
            // 30 82 ... = SEQUENCE
            return apdu.tagClass() == TAG_CLASS_UNIVERSAL
                && apdu.constructed()
                && apdu.tagNumber() == 16
                && encodedApdu.length > 80;

        } catch (RuntimeException ex) {
            return false;
        }
    }

    public SubmitRequest decodeSubmitRequest(byte[] encodedApdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedApdu);
        if (apdu.tagClass() == TAG_CLASS_CONTEXT && apdu.constructed() && apdu.tagNumber() == SUBMIT_REQUEST_TAG) {
            Map<Integer, String> fields = decodeContextUtf8Fields(apdu.value());
            return new SubmitRequest(value(fields.get(0)), value(fields.get(1)), value(fields.get(2)), encodedApdu);
        }
        if (apdu.tagClass() == TAG_CLASS_UNIVERSAL && apdu.constructed() && apdu.tagNumber() == 16) {
        	
        	/** Managing AMHS Priority **/
        	AMHSPriority priority = extractAmhsPriority(apdu);
        	logger.info( "AMHS submission priority={} value={}", priority.label(), priority.value() );
            List<String> orAddresses = new ArrayList<>();
            collectOrAddresses(apdu, orAddresses);
            String recipient = orAddresses.size() >= 2 ? orAddresses.get(1) : "";
            String subject = "";
            String body = extractBodyText(apdu);
            
            /** Managing AFTN Priority + Filing time **/
            AftnHeader aftnHeader = extractAftnHeader(body);
            if (aftnHeader.priority() != null)
                logger.info("AFTN priority={}", aftnHeader.priority() );
            if (aftnHeader.filingTime() != null)
                logger.info("AFTN filing time={} format=DDHHMM UTC", aftnHeader.filingTime() );
            return new SubmitRequest(recipient, subject, body, encodedApdu);
        }
        throw new IllegalArgumentException("Not a submit request APDU");
    }
    
    private AMHSPriority extractAmhsPriority(BerTlv submitArgument) {
        if (submitArgument == null || submitArgument.tagClass() != TAG_CLASS_UNIVERSAL || submitArgument.tagNumber() != 16 || !submitArgument.constructed())
            return AMHSPriority.UNKNOWN;
        List<BerTlv> argumentFields;
        try {
            argumentFields = BerCodec.decodeAll(submitArgument.value());
        } catch (RuntimeException ex) {
            logger.warn("Unable to decode MessageSubmissionArgument", ex);
            return AMHSPriority.UNKNOWN;
        }
        BerTlv envelope = argumentFields.stream()
            .filter(field -> field.tagClass() == TAG_CLASS_UNIVERSAL && field.tagNumber() == 17 && 
            field.constructed()).findFirst().orElse(null);
        if (envelope == null) {
            logger.warn("MessageSubmissionEnvelope was not found");
            return AMHSPriority.UNKNOWN;
        }
        try {
            for (BerTlv field : BerCodec.decodeAll(envelope.value())) {
                /* Priority ::= [APPLICATION 7] ENUMERATED { normal(0), non-urgent(1), urgent(2) } */
                if (field.tagClass() == TAG_CLASS_APPLICATION && field.tagNumber() == AMHS_PRIORITY_APPLICATION_TAG && !field.constructed()) {
                    byte[] value = field.value();
                    if (value == null || value.length != 1) {
                        logger.warn("Invalid AMHS priority encoding: expected one byte, got {}", value == null ? 0 : value.length);
                        return AMHSPriority.UNKNOWN;
                    }
                    int numericValue = value[0] & 0xFF;
                    return AMHSPriority.fromValue(numericValue);
                }
            }
        } catch (RuntimeException ex) {
            logger.warn("Unable to decode MessageSubmissionEnvelope", ex);
            return AMHSPriority.UNKNOWN;
        }
        return AMHSPriority.NORMAL;
    }
    
    private AftnHeader extractAftnHeader(String body) {
        if (!StringUtils.hasText(body))
            return new AftnHeader(null, null);
        AFTNPriority priority = null;
        String filingTime = null;
        String[] lines = body.split("\\R");
        /* AFTN header information should be near the beginning of the message.
         * Limiting the scan also reduces the chance of matching message content. */
        int linesToInspect = Math.min(lines.length, 10);
        for (int i = 0; i < linesToInspect; i++) {
            String line = lines[i].trim();
            if (line.isEmpty())
                continue;
            if (priority == null) {
                Matcher priorityMatcher = AFTN_PRIORITY_LINE.matcher(line);
                if (priorityMatcher.find()) {
                    try {
                        priority = AFTNPriority.valueOf(priorityMatcher.group(1));
                    } catch (IllegalArgumentException ignored) { }
                }
            }
            if (filingTime == null) {
                Matcher filingTimeMatcher = AFTN_FILING_TIME_LINE.matcher(line);
                if (filingTimeMatcher.matches())
                    filingTime = filingTimeMatcher.group(1);
            }
            if (priority != null && filingTime != null)
                break;
        }
        return new AftnHeader(priority, filingTime);
    }
    
    private String extractBodyText(BerTlv root) {
        List<String> texts = new ArrayList<>();
        collectBodyText(root, texts);
        return texts.stream()
            .map(String::trim).filter(s -> !s.isBlank()).filter(this::looksLikeBodyText)
            .max(java.util.Comparator.comparingInt(String::length)).orElse("");
    }
    
    private boolean looksLikeBodyText(String text) {
        if (text.length() < 10)
            return false;
        // Reject OR-address fragments
        if (text.startsWith("/C=") || text.startsWith("/ADMD="))
            return false;
        // Reject all-uppercase routing identifiers
        if (text.matches("[A-Z0-9]{2,12}"))
            return false;
        return true;
    }

    private void collectBodyText(BerTlv node, List<String> out) {
        if (node == null) {
            return;
        }
        try {
            if (!node.constructed()) {
                int tag = node.tagNumber();
                // UTF8String, PrintableString, IA5String, VisibleString, GeneralString
                if (tag == 12 || tag == 19 || tag == 22 || tag == 26 || tag == 27) {
                    String text = new String(node.value(), java.nio.charset.StandardCharsets.UTF_8).trim();
                    if (!text.isBlank()) {
                        out.add(text);
                    }
                }
                // OCTET STRING may contain nested BER body content
                if (tag == 4 && node.value() != null && node.value().length > 2) {
                    try {
                        BerTlv nested = BerCodec.decodeSingle(node.value());
                        collectBodyText(nested, out);
                    } catch (RuntimeException ignored) {
                        String raw = new String(node.value(), java.nio.charset.StandardCharsets.UTF_8).trim();
                        if (!raw.isBlank()) {
                            out.add(raw);
                        }
                    }
                }
                return;
            }
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                collectBodyText(child, out);
            }
        } catch (RuntimeException ignored) {
        }
    }
    
    private void collectOrAddresses(BerTlv node, List<String> out) {
        if (node == null || !node.constructed()) {
            return;
        }

        try {
            List<BerTlv> children = BerCodec.decodeAll(node.value());
            Map<String, String> attrs = new HashMap<>();

            for (BerTlv child : children) {
                String text = firstText(child);
                if (text == null || text.isBlank()) {
                    continue;
                }

                int cls = child.tagClass();
                int tag = child.tagNumber();

                // From BER:
                // 61 -> C
                // 62 -> ADMD
                // A2 -> PRMD
                // 83 -> O
                // A6 -> OU1
                if (cls == TAG_CLASS_APPLICATION && tag == 1) {
                    attrs.put("C", text);
                } else if (cls == TAG_CLASS_APPLICATION && tag == 2) {
                    attrs.put("ADMD", text);
                } else if (cls == TAG_CLASS_CONTEXT && tag == 2) {
                    attrs.put("PRMD", text);
                } else if (cls == TAG_CLASS_CONTEXT && tag == 3) {
                    attrs.put("O", text);
                } else if (cls == TAG_CLASS_CONTEXT && tag == 6) {
                    attrs.put("OU1", text);
                }
            }

            if (attrs.containsKey("C") && attrs.containsKey("ADMD")) {
                String addr =
                    "/C=" + attrs.getOrDefault("C", "") +
                    "/ADMD=" + attrs.getOrDefault("ADMD", "") +
                    "/PRMD=" + attrs.getOrDefault("PRMD", "") +
                    "/O=" + attrs.getOrDefault("O", "") +
                    "/OU1=" + attrs.getOrDefault("OU1", "");

                if (!out.contains(addr)) {
                    out.add(addr);
                }
            }

            for (BerTlv child : children) {
                collectOrAddresses(child, out);
            }
        } catch (RuntimeException ignored) {
        }
    }

    private String firstText(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            if (!node.constructed()) {
                int cls = node.tagClass();
                int tag = node.tagNumber();

                if (tag == 12 || tag == 19 || tag == 22 || tag == 26 || tag == 27) {
                    return new String(node.value(), java.nio.charset.StandardCharsets.UTF_8);
                }

                // Needed for O=technosky: 83 09 ...
                if (cls == TAG_CLASS_CONTEXT && node.value() != null && node.value().length > 0) {
                    return new String(node.value(), java.nio.charset.StandardCharsets.UTF_8);
                }

                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                String text = firstText(child);
                if (text != null && !text.isBlank()) {
                    return text;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    public byte[] encodeSubmitResult(SubmitResult result, String senderOrAddress) {
        String id = StringUtils.hasText(result.internalMessageId())
            ? result.internalMessageId()
            : result.submissionId();

        byte[] opCode = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { 0x03 })
        );

        byte[] mtsResult = encodeMtsResult(id, senderOrAddress);

        byte[] resultValue = concat(List.of(opCode, mtsResult));

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, resultValue.length, resultValue)
        );
    }
    
    private byte[] encodeMtsResult(String id, String senderOrAddress) {
        String safe = StringUtils.hasText(id) ? id : UUID.randomUUID().toString();
        ORAddress sender = ORAddress.parse(senderOrAddress);

        String timestampWithSeconds = X400_LOCAL_ID_TIME_FORMAT.format(Instant.now());
        String timestampWithoutSeconds = X400_SUBMISSION_TIME_FORMAT.format(Instant.now());

        String localId = buildLocalIdentifier(timestampWithSeconds);

        byte[] globalDomainIdentifier = encodeGlobalDomainIdentifier(sender);

        byte[] localIdentifier = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                false,
                22,
                0,
                localId.length(),
                localId.getBytes(StandardCharsets.US_ASCII)
            )
        );

        byte[] submissionIdentifierValue = concat(List.of(
            globalDomainIdentifier,
            localIdentifier
        ));

        byte[] messageSubmissionIdentifier = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                4,
                0,
                submissionIdentifierValue.length,
                submissionIdentifierValue
            )
        );

        
        byte[] messageSubmissionTime = BerCodec.encode(
    	    new BerTlv(
    	        TAG_CLASS_CONTEXT,
    	        false,
    	        0,
    	        0,
    	        timestampWithoutSeconds.length(),
    	        timestampWithoutSeconds.getBytes(StandardCharsets.US_ASCII)
    	    )
    	);

        byte[] mtsResultValue = concat(List.of(messageSubmissionIdentifier, messageSubmissionTime));
        return BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, true, 17, 0, mtsResultValue.length, mtsResultValue));
    }
    
    private String buildLocalIdentifier(String timestamp) {
        String date = timestamp.substring(0, 6);
        String time = timestamp.substring(6, 12);

        return localIdCountry
            + "-"
            + localIdCity
            + "-"
            + localIdNode
            + "."
            + localIdSequence
            + "-"
            + date
            + "."
            + time;
    }

    private byte[] encodeGlobalDomainIdentifier(ORAddress sender) {
        List<byte[]> parts = new ArrayList<>();

        addPrintableApplication(parts, 1, sender.get("C"));
        addPrintableApplication(parts, 2, sender.get("ADMD"));

        String prmd = sender.get("PRMD");
        if (StringUtils.hasText(prmd)) {
            parts.add(encodePrintableString(prmd)); // IMPORTANT: bare 13 xx, not A2
        }

        byte[] value = concat(parts);

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, 3, 0, value.length, value)
        );
    }

    private void addPrintableApplication(List<byte[]> parts, int tag, String value) {
        if (!StringUtils.hasText(value)) {
            return;
        }

        byte[] inner = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 19, 0,
                value.length(),
                value.getBytes(StandardCharsets.US_ASCII))
        );

        parts.add(BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, tag, 0, inner.length, inner)
        ));
    }

    private byte[] encodePrintableString(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 19, 0, bytes.length, bytes)
        );
    }

    public byte[] encodeSubmitError(P3Error error) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, error.code()));
        fields.add(encodeUtf8ContextField(1, error.detail()));
        fields.add(encodeUtf8ContextField(2, Boolean.toString(error.retryable())));

        byte[] payload = concat(fields);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, ERROR_TAG, 0, payload.length, payload));
    }

    private Map<Integer, String> decodeContextUtf8Fields(byte[] payload) {
        Map<Integer, String> values = new HashMap<>();
        for (BerTlv field : decodeContextFieldList(payload)) {
            if (field.tagClass() != TAG_CLASS_CONTEXT) {
                continue;
            }

            if (field.constructed()) {
                List<String> atoms = collectTextualAtoms(field);
                if (!atoms.isEmpty()) {
                    values.put(field.tagNumber(), atoms.get(0));
                }
            } else {
                values.put(field.tagNumber(), new String(field.value(), java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private String value(String maybeNull) {
        return maybeNull == null ? "" : maybeNull;
    }
}