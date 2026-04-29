package it.technosky.server.p3.service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

import it.technosky.server.p3.address.ORAddress;
import it.technosky.server.p3.address.ORNameMapper;
import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.domain.AMHSDeliveryStatus;
import it.technosky.server.p3.x411.X411Diagnostic;
import it.technosky.server.p3.x411.X411TagMap;

/**
 * Minimal X.411-oriented report APDU encoder used to materialize a wire-level report structure
 * from persistence entities before transport integration.
 */
public class X411DeliveryReportApduCodec {

    public byte[] encodeNonDeliveryReport(NonDeliveryReportApdu report) {
        if (report.reportedRecipientInfo() == null || report.reportedRecipientInfo().isEmpty()) {
            throw new IllegalArgumentException("NonDeliveryReport requires at least one ReportedRecipientInfo");
        }
        byte[] payload = concat(
            encodeMtsIdentifier(report.mtsIdentifier(), report.reportedRecipientInfo()),
            encodeBoolean(1, report.returnOfContent()),
            encodeReportedRecipientInfo(report.reportedRecipientInfo()),
            encodeOptionalIa5(3, report.nonDeliveryReason())
        );
        return BerCodec.encode(
            new BerTlv(X411TagMap.TAG_CLASS_APPLICATION, true, X411TagMap.APDU_NON_DELIVERY_REPORT, 0, payload.length, payload)
        );
    }

    public ValidationResult validateEncodedNonDeliveryReport(byte[] apdu) {
        BerTlv tlv = BerCodec.decodeSingle(apdu);
        if (!tlv.constructed()) {
            throw new IllegalArgumentException("NonDeliveryReport APDU must be constructed");
        }
        if (tlv.tagClass() != X411TagMap.TAG_CLASS_APPLICATION) {
            throw new IllegalArgumentException("NonDeliveryReport APDU must use APPLICATION tag class");
        }
        if (tlv.tagNumber() != X411TagMap.APDU_NON_DELIVERY_REPORT) {
            throw new IllegalArgumentException("Unexpected APDU tag for NonDeliveryReport");
        }
        List<BerTlv> fields = BerCodec.decodeAll(tlv.value());
        ensureRequiredField(fields, 0, "mtsIdentifier");
        ensureRequiredField(fields, 1, "returnOfContent");
        ensureRequiredField(fields, 2, "reportedRecipientInfo");
        return new ValidationResult(tlv.tagClass(), tlv.tagNumber(), fields.size());
    }

    private void ensureRequiredField(List<BerTlv> fields, int tag, String fieldName) {
        BerTlv field = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, tag)
            .orElseThrow(() -> new IllegalArgumentException("Missing report field '" + fieldName + "'"));
        X411TagMap.validateContextTagClass(field.tagClass(), fieldName);
    }

    public NonDeliveryReportApdu decodeNonDeliveryReport(byte[] apdu) {
        BerTlv tlv = BerCodec.decodeSingle(apdu);
        if (tlv.tagClass() != X411TagMap.TAG_CLASS_APPLICATION || !tlv.constructed() || tlv.tagNumber() != X411TagMap.APDU_NON_DELIVERY_REPORT) {
            throw new IllegalArgumentException("Unexpected APDU tag for NonDeliveryReport");
        }
        List<BerTlv> fields = BerCodec.decodeAll(tlv.value());
        String mtsId = decodeMtsIdentifier(fields);
        boolean returnContent = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 1)
            .map(flag -> flag.value().length > 0 && flag.value()[0] != 0)
            .orElse(false);
        List<ReportedRecipientInfo> recipients = decodeRecipients(fields);
        String reason = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 3)
            .map(v -> new String(v.value(), StandardCharsets.US_ASCII))
            .orElse(null);
        return new NonDeliveryReportApdu(mtsId, returnContent, recipients, reason);
    }

    private String decodeMtsIdentifier(List<BerTlv> fields) {
        BerTlv mtsField = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 0)
            .orElseThrow(() -> new IllegalArgumentException("Missing report field 'mtsIdentifier'"));
        if (!mtsField.constructed()) {
            String legacy = new String(mtsField.value(), StandardCharsets.US_ASCII).trim();
            if (legacy.isBlank()) {
                throw new IllegalArgumentException("Missing report field 'mtsIdentifier'");
            }
            return legacy;
        }

        List<BerTlv> mtsFields = BerCodec.decodeAll(mtsField.value());
        if (BerCodec.findOptional(mtsFields, X411TagMap.TAG_CLASS_CONTEXT, 1).isPresent()) {
            return decodeRequiredIa5(mtsFields, 1, "mtsIdentifier.messageIdentifier.localIdentifier");
        }
        return decodeRequiredIa5(mtsFields, 0, "mtsIdentifier.localIdentifier");
    }

    private List<ReportedRecipientInfo> decodeRecipients(List<BerTlv> fields) {
        BerTlv container = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 2)
            .orElseThrow(() -> new IllegalArgumentException("Missing reported-recipient-info"));
        List<BerTlv> items = BerCodec.decodeAll(container.value());
        if (items.isEmpty()) {
            throw new IllegalArgumentException("reported-recipient-info must not be empty");
        }
        return items.stream().map(item -> {
            List<BerTlv> recipientFields = BerCodec.decodeAll(item.value());
            String recipient = decodeRecipient(recipientFields);
            String statusValue = decodeDeliveryStatus(recipientFields);
            Integer diagnostic = BerCodec.findOptional(recipientFields, X411TagMap.TAG_CLASS_CONTEXT, 2)
                .map(this::decodeDiagnosticCode)
                .orElse(null);
            return new ReportedRecipientInfo(recipient, statusValue, diagnostic);
        }).toList();
    }

    private byte[] encodeReportedRecipientInfo(List<ReportedRecipientInfo> recipients) {
        byte[] content = concat(recipients.stream().map(this::encodeRecipientInfo).toArray(byte[][]::new));
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 2, 0, content.length, content));
    }

    private byte[] encodeRecipientInfo(ReportedRecipientInfo info) {
        byte[] value = concat(
            encodeRecipient(info.recipient()),
            encodeDeliveryStatus(info.deliveryStatus()),
            encodeOptionalDiagnostic(2, info.diagnosticCode())
        );
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 16, 0, value.length, value));
    }

    private byte[] encodeMtsIdentifier(String mtsIdentifier, List<ReportedRecipientInfo> recipients) {
        byte[] localIdentifier = encodeIa5(1, mtsIdentifier);
        byte[] globalDomainIdentifier = deriveGlobalDomainIdentifier(recipients);
        byte[] mtsContent = globalDomainIdentifier.length == 0
            ? encodeIa5(0, mtsIdentifier)
            : concat(globalDomainIdentifier, localIdentifier);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 0, 0, mtsContent.length, mtsContent));
    }

    private byte[] deriveGlobalDomainIdentifier(List<ReportedRecipientInfo> recipients) {
        if (recipients == null || recipients.isEmpty()) {
            return new byte[0];
        }
        ORAddress address = ORAddress.parse(recipients.get(0).recipient().trim());
        String country = address.get("C");
        String admd = address.get("ADMD");
        String prmd = address.get("PRMD");
        if (country == null || admd == null || prmd == null) {
            return new byte[0];
        }
        byte[] content = concat(
            encodeExplicitPrintable(0, country),
            encodeExplicitPrintable(1, admd),
            encodeOptionalExplicitPrintable(2, prmd)
        );
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 0, 0, content.length, content));
    }

    private byte[] encodeRecipient(String recipient) {
        if (recipient == null || recipient.isBlank()) {
            throw new IllegalArgumentException("Required report field is blank [recipient]");
        }
        ORAddress address = ORAddress.parse(recipient.trim());
        byte[] addressContent = concat(address.attributes().entrySet().stream()
            .map(entry -> encodeAddressAttribute(entry.getKey(), entry.getValue()))
            .toArray(byte[][]::new));
        byte[] orAddress = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 1, 0, addressContent.length, addressContent));
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 0, 0, orAddress.length, orAddress));
    }

    private byte[] encodeAddressAttribute(String key, String value) {
        int tag = mapAddressAttributeTag(key);
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, tag, 0, bytes.length, bytes));
    }

    private int mapAddressAttributeTag(String key) {
        String normalized = key.toUpperCase(Locale.ROOT);
        if (normalized.startsWith("EXT-CTX-")) {
            return Integer.parseInt(normalized.substring("EXT-CTX-".length()));
        }
        return switch (normalized) {
            case "C" -> 0;
            case "A", "ADMD" -> 1;
            case "P", "PRMD" -> 2;
            case "O" -> 3;
            case "OU1" -> 4;
            case "OU2" -> 5;
            case "OU3" -> 6;
            case "OU4" -> 7;
            case "CN" -> 8;
            case "S" -> 9;
            case "G" -> 10;
            case "I" -> 11;
            case "NUMUID" -> 12;
            default -> throw new IllegalArgumentException("Unsupported structured O/R attribute tag mapping: " + key);
        };
    }

    private String decodeRecipient(List<BerTlv> fields) {
        BerTlv recipientField = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 0)
            .orElseThrow(() -> new IllegalArgumentException("Missing report field 'recipient'"));

        if (!recipientField.constructed()) {
            return decodeRequiredIa5(fields, 0, "recipient");
        }

        return ORNameMapper.fromBer(recipientField).orAddress().toCanonicalString();
    }

    private byte[] encodeDeliveryStatus(String status) {
        if (status == null || status.isBlank()) {
            throw new IllegalArgumentException("Required report field is blank [status]");
        }
        int code = deliveryStatusToCode(status);
        byte[] value = encodeInteger(code);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, value.length, value));
    }

    private String decodeDeliveryStatus(List<BerTlv> fields) {
        BerTlv statusField = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 1)
            .orElseThrow(() -> new IllegalArgumentException("Missing report field 'status'"));
        if (looksLikeAscii(statusField.value())) {
            return new String(statusField.value(), StandardCharsets.US_ASCII).trim();
        }
        return deliveryStatusFromCode(decodeInteger(statusField.value()));
    }

    private Integer decodeDiagnosticCode(BerTlv tlv) {
        if (tlv.constructed()) {
            List<BerTlv> components = BerCodec.decodeAll(tlv.value());
            int reason = BerCodec.findOptional(components, X411TagMap.TAG_CLASS_CONTEXT, 0)
                .map(value -> decodeInteger(value.value()))
                .orElse(X411Diagnostic.ReasonCode.UNABLE_TO_TRANSFER.code());
            int diagnostic = BerCodec.findOptional(components, X411TagMap.TAG_CLASS_CONTEXT, 1)
                .map(value -> decodeInteger(value.value()))
                .orElse(X411Diagnostic.DEFAULT_DIAGNOSTIC_CODE);
            if (!X411Diagnostic.ReasonCode.fromCodeOptional(reason).isPresent()) {
                throw new IllegalArgumentException("Unsupported X.411 reason-code " + reason);
            }
            if (!X411Diagnostic.isValidDiagnosticCode(diagnostic)) {
                throw new IllegalArgumentException("Unsupported X.411 diagnostic-code " + diagnostic);
            }
            return diagnostic;
        }
        if (looksLikeAscii(tlv.value())) {
            return ReportedRecipientInfo.parseDiagnosticCode(new String(tlv.value(), StandardCharsets.US_ASCII));
        }
        return decodeInteger(tlv.value());
    }

    private boolean looksLikeAscii(byte[] value) {
        if (value == null || value.length == 0) {
            return false;
        }
        for (byte b : value) {
            int code = b & 0xFF;
            if (code < 0x20 || code > 0x7E) {
                return false;
            }
        }
        return true;
    }

    private int deliveryStatusToCode(String status) {
        return switch (status.trim().toUpperCase(Locale.ROOT)) {
            case "SUCCESS", "DELIVERED" -> 0;
            case "FAILURE", "FAILED", "EXPIRED" -> 1;
            case "DELAYED", "DEFERRED" -> 2;
            case "RELAYED" -> 3;
            case "EXPANDED" -> 4;
            case "REDIRECTED" -> 5;
            default -> throw new IllegalArgumentException("Unsupported deliveryStatus: " + status);
        };
    }

    private String deliveryStatusFromCode(int code) {
        return switch (code) {
            case 0 -> "SUCCESS";
            case 1 -> "FAILURE";
            case 2 -> "DELAYED";
            case 3 -> "RELAYED";
            case 4 -> "EXPANDED";
            case 5 -> "REDIRECTED";
            default -> throw new IllegalArgumentException("Unsupported delivery status code: " + code);
        };
    }



    private byte[] encodeOptionalDiagnostic(int tag, Integer diagnosticCode) {
        if (diagnosticCode == null) {
            return new byte[0];
        }
        int normalizedDiagnostic = X411Diagnostic.isValidDiagnosticCode(diagnosticCode)
            ? diagnosticCode
            : X411Diagnostic.DEFAULT_DIAGNOSTIC_CODE;
        int reasonCode = X411Diagnostic.ReasonCode.UNABLE_TO_TRANSFER.code();
        byte[] payload = concat(
            encodeTaggedInteger(0, reasonCode),
            encodeTaggedInteger(1, normalizedDiagnostic)
        );
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, tag, 0, payload.length, payload));
    }

    private byte[] encodeTaggedInteger(int tag, int value) {
        byte[] bytes = encodeInteger(value);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, tag, 0, bytes.length, bytes));
    }

    private byte[] encodeExplicitPrintable(int tag, String value) {
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        byte[] printable = BerCodec.encode(new BerTlv(0, false, 19, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, tag, 0, printable.length, printable));
    }

    private byte[] encodeOptionalExplicitPrintable(int tag, String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        return encodeExplicitPrintable(tag, value);
    }

    private byte[] encodeIa5(int tag, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required report field is blank [tag=" + tag + "]");
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, tag, 0, bytes.length, bytes));
    }

    private String decodeRequiredIa5(List<BerTlv> fields, int tag, String field) {
        return BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, tag)
            .map(v -> new String(v.value(), StandardCharsets.US_ASCII))
            .filter(s -> !s.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("Missing report field '" + field + "'"));
    }

    private byte[] encodeOptionalIa5(int tag, String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, tag, 0, bytes.length, bytes));
    }

    private byte[] encodeBoolean(int tag, boolean value) {
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, tag, 0, 1, new byte[] {(byte) (value ? 0xFF : 0x00)}));
    }

    private byte[] encodeOptionalInteger(int tag, Integer value) {
        if (value == null) {
            return new byte[0];
        }
        if (value < 0) {
            throw new IllegalArgumentException("INTEGER value must be non-negative");
        }
        byte[] bytes = encodeInteger(value);
        return BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] encodeInteger(int value) {
        if (value == 0) {
            return new byte[] {0x00};
        }
        int temp = value;
        int size = 0;
        byte[] buffer = new byte[5];
        while (temp > 0) {
            buffer[buffer.length - 1 - size] = (byte) (temp & 0xFF);
            temp >>>= 8;
            size++;
        }
        int start = buffer.length - size;
        if ((buffer[start] & 0x80) != 0) {
            start--;
            buffer[start] = 0x00;
            size++;
        }
        byte[] out = new byte[size];
        System.arraycopy(buffer, start, out, 0, size);
        return out;
    }

    private static int decodeInteger(byte[] value) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException("Invalid INTEGER encoding");
        }
        int result = 0;
        for (byte b : value) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }

    private static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            if (chunk != null) {
                len += chunk.length;
            }
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            if (chunk == null || chunk.length == 0) {
                continue;
            }
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }

    public record NonDeliveryReportApdu(
        String mtsIdentifier,
        boolean returnOfContent,
        List<ReportedRecipientInfo> reportedRecipientInfo,
        String nonDeliveryReason
    ) {
    }

    public record ValidationResult(int tagClass, int tagNumber, int fieldCount) {
    }

    public record ReportedRecipientInfo(String recipient, String deliveryStatus, Integer diagnosticCode) {
        public static ReportedRecipientInfo from(String recipient, AMHSDeliveryStatus status, String diagnosticCode) {
            return new ReportedRecipientInfo(recipient, status.name(), parseDiagnosticCode(diagnosticCode));
        }

        private static Integer parseDiagnosticCode(String diagnosticCode) {
            if (diagnosticCode == null || diagnosticCode.isBlank()) {
                return null;
            }
            String normalized = diagnosticCode.trim().toUpperCase(Locale.ROOT);
            if (normalized.startsWith("X411:")) {
                normalized = normalized.substring(5);
            }
            try {
                int value = Integer.parseInt(normalized);
                if (!X411Diagnostic.isValidDiagnosticCode(value)) {
                    throw new IllegalArgumentException("Invalid diagnosticCode value: " + diagnosticCode);
                }
                return value;
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid diagnosticCode value: " + diagnosticCode, ex);
            }
        }
    }
}
