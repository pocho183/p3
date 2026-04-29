package it.technosky.server.p3.acse;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class AcseModels {

    private AcseModels() {
    }

    public sealed interface AcseApdu permits AARQApdu, AAREApdu, ABRTApdu, RLRQApdu, RLREApdu {
    }

    public record ApTitle(Optional<String> objectIdentifier, byte[] rawBerBytes) {

        public ApTitle(String objectIdentifier) {
            this(Optional.ofNullable(objectIdentifier), new byte[0]);
        }

        public ApTitle(byte[] rawBerBytes) {
            this(Optional.empty(), rawBerBytes == null ? new byte[0] : rawBerBytes.clone());
        }

        public static ApTitle fromOid(String objectIdentifier) {
            return new ApTitle(objectIdentifier);
        }

        public static ApTitle fromRawBer(byte[] rawBerBytes) {
            return new ApTitle(rawBerBytes);
        }

        public ApTitle {
            objectIdentifier = objectIdentifier == null ? Optional.empty() : objectIdentifier;
            rawBerBytes = rawBerBytes == null ? new byte[0] : rawBerBytes.clone();

            if (objectIdentifier.isPresent() && objectIdentifier.get().isBlank()) {
                throw new IllegalArgumentException("ACSE AP-title object identifier must not be empty");
            }
            if (objectIdentifier.isPresent() && rawBerBytes.length > 0) {
                throw new IllegalArgumentException("ACSE AP-title cannot contain both object identifier and raw BER");
            }
            if (objectIdentifier.isEmpty() && rawBerBytes.length == 0) {
                throw new IllegalArgumentException("ACSE AP-title must contain either object identifier or raw BER");
            }
        }

        public boolean isOidForm() {
            return objectIdentifier.isPresent();
        }

        public boolean isRawBerForm() {
            return rawBerBytes.length > 0;
        }

        @Override
        public byte[] rawBerBytes() {
            return rawBerBytes.clone();
        }
    }

    public record AeQualifier(int value) {
        public AeQualifier {
            if (value < 0) {
                throw new IllegalArgumentException("ACSE AE-qualifier must be non-negative");
            }
        }
    }

    public record ResultSourceDiagnostic(int source, int diagnostic) {
        public ResultSourceDiagnostic {
            if (source != 1 && source != 2) {
                throw new IllegalArgumentException("ACSE result-source-diagnostic source must be 1 or 2");
            }
            if (diagnostic < 0) {
                throw new IllegalArgumentException("ACSE result-source-diagnostic must be non-negative");
            }
        }
    }

    public record AARQApdu(
        String applicationContextName,
        Optional<String> callingAeTitle,
        Optional<String> calledAeTitle,
        Optional<ApTitle> callingApTitle,
        Optional<AeQualifier> callingAeQualifier,
        Optional<ApTitle> calledApTitle,
        Optional<AeQualifier> calledAeQualifier,
        Optional<byte[]> authenticationValue,
        Optional<byte[]> userInformation,
        List<String> presentationContextOids,
        List<PresentationContext> presentationContexts
    ) implements AcseApdu {

        public AARQApdu(String applicationContextName, Optional<String> callingAeTitle, Optional<String> calledAeTitle) {
            this(
                applicationContextName,
                callingAeTitle,
                calledAeTitle,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                List.of(),
                List.of()
            );
        }

        public AARQApdu(
            String applicationContextName,
            Optional<String> callingAeTitle,
            Optional<String> calledAeTitle,
            Optional<ApTitle> callingApTitle,
            Optional<AeQualifier> callingAeQualifier,
            Optional<ApTitle> calledApTitle,
            Optional<AeQualifier> calledAeQualifier,
            Optional<byte[]> authenticationValue,
            Optional<byte[]> userInformation,
            List<String> presentationContextOids
        ) {
            this(
                applicationContextName,
                callingAeTitle,
                calledAeTitle,
                callingApTitle,
                callingAeQualifier,
                calledApTitle,
                calledAeQualifier,
                authenticationValue,
                userInformation,
                presentationContextOids,
                List.of()
            );
        }

        public AARQApdu {
            if (applicationContextName == null || applicationContextName.isBlank()) {
                throw new IllegalArgumentException("ACSE application-context-name is required");
            }

            callingAeTitle = normalizeOptionalString(callingAeTitle);
            calledAeTitle = normalizeOptionalString(calledAeTitle);
            callingApTitle = normalizeOptional(callingApTitle);
            callingAeQualifier = normalizeOptional(callingAeQualifier);
            calledApTitle = normalizeOptional(calledApTitle);
            calledAeQualifier = normalizeOptional(calledAeQualifier);
            authenticationValue = copyOptionalBytes(authenticationValue);
            userInformation = copyOptionalBytes(userInformation);
            presentationContextOids = List.copyOf(presentationContextOids == null ? List.of() : presentationContextOids);
            presentationContexts = List.copyOf(presentationContexts == null ? List.of() : presentationContexts);

            validateAeIdentity("calling", callingAeTitle, callingAeQualifier);
            validateAeIdentity("called", calledAeTitle, calledAeQualifier);
        }
    }

    public record AAREApdu(
        Optional<String> applicationContextName,
        boolean accepted,
        Optional<String> diagnostic,
        Optional<ResultSourceDiagnostic> resultSourceDiagnostic,
        Optional<ApTitle> respondingApTitle,
        Optional<AeQualifier> respondingAeQualifier,
        Optional<String> respondingAeTitle,
        Optional<byte[]> userInformation,
        List<String> presentationContextOids,
        Set<Integer> acceptedPresentationContextIds
    ) implements AcseApdu {

        public AAREApdu(boolean accepted, Optional<String> diagnostic) {
            this(
                Optional.empty(),
                accepted,
                diagnostic,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                List.of(),
                Set.of()
            );
        }

        public AAREApdu(
            Optional<String> applicationContextName,
            boolean accepted,
            Optional<String> diagnostic,
            Optional<ResultSourceDiagnostic> resultSourceDiagnostic,
            Optional<byte[]> userInformation,
            List<String> presentationContextOids
        ) {
            this(
                applicationContextName,
                accepted,
                diagnostic,
                resultSourceDiagnostic,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                userInformation,
                presentationContextOids,
                Set.of()
            );
        }

        public AAREApdu {
            applicationContextName = normalizeOptionalString(applicationContextName);
            diagnostic = normalizeOptionalString(diagnostic);
            resultSourceDiagnostic = normalizeOptional(resultSourceDiagnostic);
            respondingApTitle = normalizeOptional(respondingApTitle);
            respondingAeQualifier = normalizeOptional(respondingAeQualifier);
            respondingAeTitle = normalizeOptionalString(respondingAeTitle);
            userInformation = copyOptionalBytes(userInformation);
            presentationContextOids = List.copyOf(presentationContextOids == null ? List.of() : presentationContextOids);
            acceptedPresentationContextIds = Set.copyOf(
                acceptedPresentationContextIds == null ? Set.of() : acceptedPresentationContextIds
            );

            validateAeIdentity("responding", respondingAeTitle, respondingAeQualifier);
        }
    }

    public record ABRTApdu(String source, Optional<String> diagnostic) implements AcseApdu {
        public ABRTApdu {
            if (source == null || source.isBlank()) {
                throw new IllegalArgumentException("ACSE ABRT source is required");
            }
            diagnostic = normalizeOptionalString(diagnostic);
        }
    }

    public record RLRQApdu(Optional<String> reason) implements AcseApdu {
        public RLRQApdu {
            reason = normalizeOptionalString(reason);
        }
    }

    public record RLREApdu(boolean normal) implements AcseApdu {
    }

    public enum AssociationState {
        IDLE,
        AWAITING_AARE,
        AWAITING_AARE_RESPONSE,
        ESTABLISHED,
        AWAITING_RLRE,
        AWAITING_RLRE_RESPONSE,
        ABORTED,
        CLOSED
    }

    public static final class AssociationStateMachine {
        private AssociationState state = AssociationState.IDLE;

        public AssociationState state() {
            return state;
        }

        public void onOutbound(AcseApdu apdu) {
            transition(apdu, true);
        }

        public void onInbound(AcseApdu apdu) {
            transition(apdu, false);
        }

        private void transition(AcseApdu apdu, boolean outbound) {
            if (apdu instanceof AARQApdu) {
                require(state == AssociationState.IDLE, "AARQ only allowed in IDLE state");
                state = outbound ? AssociationState.AWAITING_AARE : AssociationState.AWAITING_AARE_RESPONSE;
                return;
            }
            if (apdu instanceof AAREApdu aare) {
                if (outbound) {
                    require(
                        state == AssociationState.AWAITING_AARE_RESPONSE,
                        "Outbound AARE only allowed after inbound AARQ"
                    );
                } else {
                    require(
                        state == AssociationState.AWAITING_AARE,
                        "Inbound AARE only allowed after outbound AARQ"
                    );
                }
                state = aare.accepted() ? AssociationState.ESTABLISHED : AssociationState.CLOSED;
                return;
            }
            if (apdu instanceof RLRQApdu) {
                require(state == AssociationState.ESTABLISHED, "RLRQ only allowed in ESTABLISHED state");
                state = outbound ? AssociationState.AWAITING_RLRE : AssociationState.AWAITING_RLRE_RESPONSE;
                return;
            }
            if (apdu instanceof RLREApdu) {
                if (outbound) {
                    require(
                        state == AssociationState.AWAITING_RLRE_RESPONSE,
                        "Outbound RLRE only allowed after inbound RLRQ"
                    );
                } else {
                    require(
                        state == AssociationState.AWAITING_RLRE,
                        "Inbound RLRE only allowed after outbound RLRQ"
                    );
                }
                state = AssociationState.CLOSED;
                return;
            }
            if (apdu instanceof ABRTApdu) {
                state = AssociationState.ABORTED;
                return;
            }
            throw new IllegalArgumentException("Unsupported ACSE APDU type: " + apdu.getClass().getSimpleName());
        }

        private void require(boolean condition, String message) {
            if (!condition) {
                throw new IllegalStateException(message + ", current=" + state);
            }
        }
    }

    private static <T> Optional<T> normalizeOptional(Optional<T> value) {
        return value == null ? Optional.empty() : value;
    }

    private static Optional<String> normalizeOptionalString(Optional<String> value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        String normalized = value.get() == null ? "" : value.get().trim();
        return normalized.isEmpty() ? Optional.empty() : Optional.of(normalized);
    }

    private static Optional<byte[]> copyOptionalBytes(Optional<byte[]> value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        byte[] bytes = value.get();
        return Optional.of(Arrays.copyOf(bytes, bytes.length));
    }

    private static void validateAeIdentity(
        String side,
        Optional<String> aeTitle,
        Optional<AeQualifier> aeQualifier
    ) {
        if (aeTitle.isPresent() && aeQualifier.isPresent()) {
            throw new IllegalArgumentException(
                "ACSE " + side + " identity cannot include both AE-title and AE-qualifier"
            );
        }
    }
}