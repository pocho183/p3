package it.technosky.server.p3.acse;

import java.util.List;
import java.util.HashSet;
import java.util.Set;

public record PresentationContext(int identifier, String abstractSyntaxOid, List<String> transferSyntaxOids) {

    public void validate() {
        if (identifier <= 0 || identifier % 2 == 0) {
            throw new IllegalArgumentException("Presentation-context identifier must be an odd positive integer");
        }
        if (abstractSyntaxOid == null || abstractSyntaxOid.isBlank()) {
            throw new IllegalArgumentException("Presentation-context abstract syntax OID is required");
        }
        if (transferSyntaxOids == null || transferSyntaxOids.isEmpty()) {
            throw new IllegalArgumentException("At least one transfer syntax must be provided");
        }
    }

    public static void validateNegotiation(List<PresentationContext> proposed, Set<Integer> acceptedIdentifiers) {
        if (proposed == null || proposed.isEmpty()) {
            throw new IllegalArgumentException("At least one presentation-context proposal is required");
        }
        if (acceptedIdentifiers == null || acceptedIdentifiers.isEmpty()) {
            throw new IllegalArgumentException("At least one presentation-context must be accepted");
        }
        Set<Integer> seenIdentifiers = new HashSet<>();
        for (PresentationContext context : proposed) {
            context.validate();
            if (!seenIdentifiers.add(context.identifier())) {
                throw new IllegalArgumentException("Duplicate proposed presentation-context identifier: " + context.identifier());
            }
        }
        for (Integer id : acceptedIdentifiers) {
            if (id == null || id <= 0 || id % 2 == 0) {
                throw new IllegalArgumentException("Accepted presentation-context identifier must be an odd positive integer");
            }
            boolean known = proposed.stream().anyMatch(candidate -> candidate.identifier == id);
            if (!known) {
                throw new IllegalArgumentException("Accepted presentation-context id not proposed: " + id);
            }
        }
    }
}
