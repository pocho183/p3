package it.technosky.server.p3.x411;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class X411DiagnosticMapper {

    private static final int DEFAULT_FAILURE_DIAGNOSTIC = X411Diagnostic.DEFAULT_DIAGNOSTIC_CODE;

    private static final Pattern DIAGNOSTIC_CODE_PATTERN = Pattern.compile("(?:^|[;,\\s])diagnostic-code\\s*[=:]\\s*([0-9]{1,3})(?:$|[;,\\s])", Pattern.CASE_INSENSITIVE);
    private static final Pattern REASON_CODE_PATTERN = Pattern.compile("(?:^|[;,\\s])reason-code\\s*[=:]\\s*([0-9]{1,3})(?:$|[;,\\s])", Pattern.CASE_INSENSITIVE);

    private static final Map<String, X411Diagnostic.ReasonCode> KEYWORD_TO_REASON = new LinkedHashMap<>();
    private static final Map<String, Integer> KEYWORD_TO_DIAGNOSTIC = new LinkedHashMap<>();

    static {
        KEYWORD_TO_REASON.put("unable-to-transfer", X411Diagnostic.ReasonCode.UNABLE_TO_TRANSFER);
        KEYWORD_TO_REASON.put("transfer-impossible", X411Diagnostic.ReasonCode.TRANSFER_IMPOSSIBLE);
        KEYWORD_TO_REASON.put("conversion-not-performed", X411Diagnostic.ReasonCode.CONVERSION_NOT_PERFORMED);
        KEYWORD_TO_REASON.put("conversion-not-allowed", X411Diagnostic.ReasonCode.CONVERSION_NOT_ALLOWED);
        KEYWORD_TO_REASON.put("content-too-large", X411Diagnostic.ReasonCode.CONTENT_TOO_LARGE);
        KEYWORD_TO_REASON.put("content-type-not-supported", X411Diagnostic.ReasonCode.CONTENT_TYPE_NOT_SUPPORTED);
        KEYWORD_TO_REASON.put("recipient-unavailable", X411Diagnostic.ReasonCode.RECIPIENT_UNAVAILABLE);
        KEYWORD_TO_REASON.put("recipient-reassigned", X411Diagnostic.ReasonCode.RECIPIENT_REASSIGNED);
        KEYWORD_TO_REASON.put("routing-failure", X411Diagnostic.ReasonCode.ROUTING_FAILURE);
        KEYWORD_TO_REASON.put("congestion", X411Diagnostic.ReasonCode.CONGESTION);
        KEYWORD_TO_REASON.put("loop-detected", X411Diagnostic.ReasonCode.LOOP_DETECTED);
        KEYWORD_TO_REASON.put("redirection-loop-detected", X411Diagnostic.ReasonCode.REDIRECTION_LOOP_DETECTED);
        KEYWORD_TO_REASON.put("distribution-list-expansion-prohibited", X411Diagnostic.ReasonCode.DISTRIBUTION_LIST_EXPANSION_PROHIBITED);
        KEYWORD_TO_REASON.put("expansion-failed", X411Diagnostic.ReasonCode.EXPANSION_FAILED);
        KEYWORD_TO_REASON.put("alternate-recipient-not-allowed", X411Diagnostic.ReasonCode.ALTERNATE_RECIPIENT_NOT_ALLOWED);
        KEYWORD_TO_REASON.put("security", X411Diagnostic.ReasonCode.SECURITY_FAILURE);
        KEYWORD_TO_REASON.put("authentication", X411Diagnostic.ReasonCode.SECURITY_FAILURE);
        KEYWORD_TO_REASON.put("syntax", X411Diagnostic.ReasonCode.CONTENT_SYNTAX_ERROR);
        KEYWORD_TO_REASON.put("validation", X411Diagnostic.ReasonCode.CONTENT_SYNTAX_ERROR);

        KEYWORD_TO_DIAGNOSTIC.put("timeout", 16);
        KEYWORD_TO_DIAGNOSTIC.put("timed out", 16);
        KEYWORD_TO_DIAGNOSTIC.put("loop", 21);
        KEYWORD_TO_DIAGNOSTIC.put("hop", 21);
        KEYWORD_TO_DIAGNOSTIC.put("route", 22);
        KEYWORD_TO_DIAGNOSTIC.put("unreachable", 22);
        KEYWORD_TO_DIAGNOSTIC.put("network", 22);
        KEYWORD_TO_DIAGNOSTIC.put("congestion", 28);
        KEYWORD_TO_DIAGNOSTIC.put("busy", 28);
        KEYWORD_TO_DIAGNOSTIC.put("content", 26);
        KEYWORD_TO_DIAGNOSTIC.put("encoding", 26);
        KEYWORD_TO_DIAGNOSTIC.put("security", 30);
        KEYWORD_TO_DIAGNOSTIC.put("certificate", 30);
        KEYWORD_TO_DIAGNOSTIC.put("authentication", 30);
        KEYWORD_TO_DIAGNOSTIC.put("policy", 31);
        KEYWORD_TO_DIAGNOSTIC.put("validation", 31);
        KEYWORD_TO_DIAGNOSTIC.put("rejected", 31);
    }

    public X411Diagnostic mapDiagnostic(String reason, String diagnostic, Integer recipientStatus) {
        String corpus = ((reason == null ? "" : reason) + " " + (diagnostic == null ? "" : diagnostic))
            .toLowerCase(Locale.ROOT);

        Integer explicitReasonCode = firstReasonCode(reason, diagnostic);
        Integer explicitDiagnosticCode = firstDiagnosticCode(reason, diagnostic);
        Integer explicitX411Code = firstX411Code(reason, diagnostic);

        X411Diagnostic.ReasonCode reasonCode = explicitReasonCode != null
            ? X411Diagnostic.ReasonCode.fromCode(explicitReasonCode)
            : inferReasonCode(corpus, recipientStatus);

        int diagnosticCode = explicitX411Code != null
            ? explicitX411Code
            : (explicitDiagnosticCode != null ? explicitDiagnosticCode : inferDiagnosticCode(corpus));

        return X411Diagnostic.of(reasonCode, normalizeDiagnosticCode(diagnosticCode));
    }

    /**
     * Strict path for BER/ASN.1-decoded reason and diagnostic codes.
     * <p>
     * Unknown reason-code values are rejected with {@link IllegalArgumentException} so
     * protocol handlers can fail-fast for conformance lab scenarios, instead of silently
     * inferring from free-form text.
     */
    public X411Diagnostic mapDiagnosticFromAsn1Codes(int reasonCode, int diagnosticCode) {
        X411Diagnostic.ReasonCode normalizedReason = X411Diagnostic.ReasonCode.fromCodeOptional(reasonCode)
            .orElseThrow(() -> new IllegalArgumentException("Unsupported X.411 reason-code " + reasonCode));
        return X411Diagnostic.of(normalizedReason, normalizeDiagnosticCode(diagnosticCode));
    }

    public String map(String reason, String diagnostic) {
        return mapDiagnostic(reason, diagnostic, null).toPersistenceCode();
    }

    private X411Diagnostic.ReasonCode inferReasonCode(String corpus, Integer recipientStatus) {
        for (Map.Entry<String, X411Diagnostic.ReasonCode> entry : KEYWORD_TO_REASON.entrySet()) {
            if (corpus.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        if (recipientStatus != null && recipientStatus == 1) {
            return X411Diagnostic.ReasonCode.CONGESTION;
        }
        return X411Diagnostic.ReasonCode.UNABLE_TO_TRANSFER;
    }

    private int inferDiagnosticCode(String corpus) {
        for (Map.Entry<String, Integer> entry : KEYWORD_TO_DIAGNOSTIC.entrySet()) {
            if (corpus.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return DEFAULT_FAILURE_DIAGNOSTIC;
    }

    private int normalizeDiagnosticCode(int diagnosticCode) {
        if (!X411Diagnostic.isValidDiagnosticCode(diagnosticCode)) {
            return DEFAULT_FAILURE_DIAGNOSTIC;
        }
        return diagnosticCode;
    }

    private Integer firstReasonCode(String... values) {
        return firstNumericCode(REASON_CODE_PATTERN, values);
    }

    private Integer firstDiagnosticCode(String... values) {
        return firstNumericCode(DIAGNOSTIC_CODE_PATTERN, values);
    }

    private Integer firstNumericCode(Pattern pattern, String... values) {
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            Matcher matcher = pattern.matcher(value);
            if (matcher.find()) {
                return Integer.parseInt(matcher.group(1));
            }
        }
        return null;
    }

    private Integer firstX411Code(String... values) {
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            String normalized = value.trim().toUpperCase(Locale.ROOT);
            if (normalized.matches("X411:[0-9]{1,3}")) {
                return Integer.parseInt(normalized.substring(5));
            }
        }
        return null;
    }
}
