package it.technosky.server.p3.compliance;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.protocol.ExtensibilityContainers.SecurityParameters;


@Component
public class SecurityLabelPolicy {

    private static final Map<String, Integer> CLASSIFICATION_ORDER = Map.of(
        "UNCLASSIFIED", 0,
        "RESTRICTED", 1,
        "CONFIDENTIAL", 2,
        "SECRET", 3,
        "TOP SECRET", 4
    );

    public ParsedLabel parse(String rawLabel) {
        if (!StringUtils.hasText(rawLabel)) {
            throw new IllegalArgumentException("Security label is required");
        }

        String normalized = rawLabel.trim().toUpperCase(Locale.ROOT);
        String[] chunks = normalized.split("\\|");
        String classification = chunks[0].trim();
        if (!CLASSIFICATION_ORDER.containsKey(classification)) {
            throw new IllegalArgumentException("Unsupported Doc 9880 security classification: " + classification);
        }

        Set<String> compartments = Arrays.stream(chunks)
            .skip(1)
            .map(String::trim)
            .filter(StringUtils::hasText)
            .peek(compartment -> {
                if (!compartment.matches("[A-Z0-9-]{2,20}")) {
                    throw new IllegalArgumentException("Invalid security label compartment: " + compartment);
                }
            })
            .collect(Collectors.collectingAndThen(
                Collectors.toCollection(LinkedHashSet::new),
                Set::copyOf
            ));

        return new ParsedLabel(classification, compartments);
    }

    public void validate(SecurityParameters parameters) {
        ParsedLabel parsed = parse(parameters.securityLabel());
        if (!StringUtils.hasText(parameters.token())) {
            throw new IllegalArgumentException("Security token is required");
        }
        if (!StringUtils.hasText(parameters.algorithmOid()) || !parameters.algorithmOid().matches("[0-9]+(\\.[0-9]+)+")) {
            throw new IllegalArgumentException("Security algorithm OID must be a dotted numeric OID");
        }

        if ("UNCLASSIFIED".equals(parsed.classification()) && !parsed.compartments().isEmpty()) {
            throw new IllegalArgumentException("UNCLASSIFIED labels cannot define compartments");
        }

        // External profile claim processing is intentionally out of scope for now.
    }

    public boolean dominates(String leftLabel, String rightLabel) {
        ParsedLabel left = parse(leftLabel);
        ParsedLabel right = parse(rightLabel);

        if (level(left.classification()) < level(right.classification())) {
            return false;
        }
        return left.compartments().containsAll(right.compartments());
    }

    private int level(String classification) {
        return CLASSIFICATION_ORDER.get(classification);
    }

    public List<String> supportedClassifications() {
        return CLASSIFICATION_ORDER.entrySet().stream()
            .sorted(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .toList();
    }

    public record ParsedLabel(String classification, Set<String> compartments) {
    }
}
