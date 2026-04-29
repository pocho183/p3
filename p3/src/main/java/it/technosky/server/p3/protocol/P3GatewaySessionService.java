package it.technosky.server.p3.protocol;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.address.ORAddress;
import it.technosky.server.p3.channel.AMHSChannelService;
import it.technosky.server.p3.channel.RelayRoutingService;
import it.technosky.server.p3.channel.RelayRoutingService.AMHSMessageEnvelope;
import it.technosky.server.p3.channel.X400MessageRequest;
import it.technosky.server.p3.channel.X400MessageService;
import it.technosky.server.p3.compliance.AMHSComplianceValidator;
import it.technosky.server.p3.compliance.SecurityLabelPolicy;
import it.technosky.server.p3.domain.AMHSChannel;
import it.technosky.server.p3.domain.AMHSDeliveryReport;
import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSMessageState;
import it.technosky.server.p3.repository.AMHSDeliveryReportRepository;
import it.technosky.server.p3.repository.AMHSMessageRepository;

@Service
public class P3GatewaySessionService {

    private static final Logger logger = LoggerFactory.getLogger(P3GatewaySessionService.class);

    private final X400MessageService x400MessageService;
    private final AMHSComplianceValidator complianceValidator;
    private final AMHSChannelService channelService;
    private final RelayRoutingService relayRoutingService;
    private final AMHSMessageRepository messageRepository;
    private final AMHSDeliveryReportRepository deliveryReportRepository;

    private final long defaultStatusWaitTimeoutMs;
    private final long defaultStatusRetryIntervalMs;

    private final boolean authRequired;
    private final String expectedUsername;
    private final String expectedPassword;

    private final String defaultProtocolIndex;
    private final String defaultProtocolAddress;
    private final String defaultServerAddress;

    private final SecurityLabelPolicy securityLabelPolicy = new SecurityLabelPolicy();
    private final ConcurrentMap<String, Long> submissionCorrelationTable = new ConcurrentHashMap<>();

    public P3GatewaySessionService(
        X400MessageService x400MessageService,
        AMHSComplianceValidator complianceValidator,
        AMHSChannelService channelService,
        RelayRoutingService relayRoutingService,
        AMHSMessageRepository messageRepository,
        AMHSDeliveryReportRepository deliveryReportRepository,
        @Value("${amhs.p3.gateway.status.wait-timeout-ms:10000}") long defaultStatusWaitTimeoutMs,
        @Value("${amhs.p3.gateway.status.retry-interval-ms:1000}") long defaultStatusRetryIntervalMs,
        @Value("${amhs.p3.gateway.auth.required:true}") boolean authRequired,
        @Value("${amhs.p3.gateway.auth.username:}") String expectedUsername,
        @Value("${amhs.p3.gateway.auth.password:}") String expectedPassword,
        @Value("${amhs.p3.gateway.protocol-index:RFC1006}") String defaultProtocolIndex,
        @Value("${amhs.p3.gateway.protocol-address:127.0.0.1:102}") String defaultProtocolAddress,
        @Value("${amhs.p3.gateway.server-address:AMHS-P3-GATEWAY}") String defaultServerAddress
    ) {
        this.x400MessageService = x400MessageService;
        this.complianceValidator = complianceValidator;
        this.channelService = channelService;
        this.relayRoutingService = relayRoutingService;
        this.messageRepository = messageRepository;
        this.deliveryReportRepository = deliveryReportRepository;
        this.defaultStatusWaitTimeoutMs = Math.max(0L, defaultStatusWaitTimeoutMs);
        this.defaultStatusRetryIntervalMs = Math.max(1L, defaultStatusRetryIntervalMs);
        this.authRequired = authRequired;
        this.expectedUsername = trimToNull(expectedUsername);
        this.expectedPassword = trimToNull(expectedPassword);
        this.defaultProtocolIndex = defaultProtocolIndex;
        this.defaultProtocolAddress = defaultProtocolAddress;
        this.defaultServerAddress = defaultServerAddress;
        
        logger.info(
        	    "P3 auth config loaded authRequired={} expectedUsername='{}' expectedPasswordLength={}",
        	    this.authRequired,
        	    this.expectedUsername,
        	    this.expectedPassword == null ? -1 : this.expectedPassword.length()
        	);
    }

    public SessionState newSession() {
        return new SessionState();
    }

    public String handleCommand(SessionState state, String rawCommand) {
        if (state.closed) {
            return "ERR code=association-closed detail=Association already released";
        }

        String trimmed = rawCommand == null ? "" : rawCommand.trim();
        if (!StringUtils.hasText(trimmed)) {
            return "ERR code=invalid-command detail=Empty command";
        }

        String[] segments = trimmed.split("\\s+", 2);
        String operation = segments[0].toUpperCase();

        ParsedAttributes parsedAttributes = segments.length > 1
            ? parseAttributes(segments[1])
            : new ParsedAttributes(Map.of(), null);

        if (parsedAttributes.error() != null) {
            logger.warn(
                "P3 command op={} rejected due to malformed attributes detail={}",
                operation,
                parsedAttributes.error()
            );
            return parsedAttributes.error();
        }

        Map<String, String> attributes = parsedAttributes.attributes();
        String attributeValidationError = validateAttributeNames(operation, attributes);
        if (attributeValidationError != null) {
            logger.warn(
                "P3 command op={} rejected due to unsupported attribute set attrs={}",
                operation,
                redactSensitiveAttributes(attributes)
            );
            return attributeValidationError;
        }

        logger.info(
            "P3 command op={} bound={} attrs={}",
            operation,
            state.bound,
            redactSensitiveAttributes(attributes)
        );

        String response = switch (operation) {
            case "BIND" -> bind(state, attributes);
            case "SUBMIT" -> submit(state, attributes);
            case "RETRIEVE", "STATUS" -> retrieveStatus(state, attributes);
            case "REPORT" -> readMailbox(state, attributes, "Report");
            case "READ" -> readMailbox(state, attributes, "Read");
            case "UNBIND", "RELEASE", "QUIT" -> unbind(state);
            default -> "ERR code=unsupported-operation detail=Unsupported operation " + operation;
        };

        logger.info("P3 command op={} result={}", operation, response);
        return response;
    }

    private String bind(SessionState state, Map<String, String> attributes) {
        if (state.bound) {
            logger.warn("P3 bind rejected: bind requested on already bound association");
            return "ERR code=association detail=Bind received on already bound association";
        }

        String providedUsername = trimToNull(attributes.get("username"));
        String providedPassword = trimToNull(attributes.get("password"));
        String senderAddress = trimToNull(attributes.get("sender"));
        String requestedChannel = trimToNull(attributes.get("channel"));
        String securityLabel = trimToNull(attributes.get("security-label"));
        String gatewayPolicyLabel = trimToNull(attributes.get("gateway-policy-label"));

        String effectiveChannel = StringUtils.hasText(requestedChannel)
            ? requestedChannel
            : AMHSChannelService.DEFAULT_CHANNEL_NAME;

        if (!StringUtils.hasText(senderAddress)) {
            logger.warn("P3 bind rejected: missing sender address");
            return "ERR code=invalid-or-address detail=Missing sender address";
        }

        final ORAddress parsedSender;
        try {
            parsedSender = ORAddress.parse(senderAddress);
            complianceValidator.validateIcaoOrAddress(parsedSender.toCanonicalString(), "sender");
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 bind rejected: invalid sender address reason={}", ex.getMessage());
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
        }

        String canonicalSender = parsedSender.toCanonicalString();

        /*
         * ICAO/P3 rule used here:
         *
         * - textual gateway bind:
         *     username + password + sender
         *
         * - native P3 bind:
         *     password + sender
         *     authenticated identity == sender O/R address
         */
        String effectiveIdentity = StringUtils.hasText(providedUsername)
            ? providedUsername
            : canonicalSender;

        if (authRequired) {
            if (!StringUtils.hasText(providedPassword)) {
                logger.warn(
                    "P3 bind rejected: authentication failed sender={} identity={} reason=missing password",
                    canonicalSender,
                    effectiveIdentity
                );
                return "ERR code=auth-failed detail=Missing credentials";
            }

            boolean gatewayCredentialMatch =
                StringUtils.hasText(providedUsername)
                    && StringUtils.hasText(expectedUsername)
                    && StringUtils.hasText(expectedPassword)
                    && expectedUsername.equals(providedUsername)
                    && expectedPassword.equals(providedPassword);

            boolean nativeP3CredentialMatch =
                !StringUtils.hasText(providedUsername)
                    && StringUtils.hasText(expectedPassword)
                    && expectedPassword.equals(providedPassword);

            if (!gatewayCredentialMatch && !nativeP3CredentialMatch) {
                logger.warn(
                    "P3 bind rejected: authentication failed sender={} identity={} reason=invalid credentials",
                    canonicalSender,
                    effectiveIdentity
                );
                return "ERR code=auth-failed detail=Invalid credentials";
            }
        }

        if (StringUtils.hasText(providedUsername)) {
            try {
                complianceValidator.validateAuthenticatedIdentityBinding(
                    canonicalSender,
                    providedUsername
                );
            } catch (IllegalArgumentException ex) {
                logger.warn(
                    "P3 bind rejected: identity binding failed identity={} sender={} reason={}",
                    providedUsername,
                    canonicalSender,
                    ex.getMessage()
                );
                return "ERR code=authz-failed detail=" + ex.getMessage();
            }
        } else {
            logger.info(
                "P3 bind native identity accepted sender={} authenticated-identity={}",
                canonicalSender,
                effectiveIdentity
            );
        }

        if (StringUtils.hasText(gatewayPolicyLabel) && !StringUtils.hasText(securityLabel)) {
            logger.warn("P3 bind rejected: gateway policy label supplied without security label");
            return "ERR code=security-policy detail=Security label is required when gateway policy label is provided";
        }

        if (StringUtils.hasText(securityLabel) || StringUtils.hasText(gatewayPolicyLabel)) {
            try {
                if (StringUtils.hasText(securityLabel)) {
                    securityLabelPolicy.parse(securityLabel);
                }
                if (StringUtils.hasText(gatewayPolicyLabel)) {
                    securityLabelPolicy.parse(gatewayPolicyLabel);
                }
                if (StringUtils.hasText(securityLabel)
                    && StringUtils.hasText(gatewayPolicyLabel)
                    && !securityLabelPolicy.dominates(securityLabel, gatewayPolicyLabel)) {
                    logger.warn(
                        "P3 bind rejected: label dominance failure security-label={} gateway-policy-label={}",
                        securityLabel,
                        gatewayPolicyLabel
                    );
                    return "ERR code=security-policy detail=Security label does not dominate gateway policy label";
                }
            } catch (IllegalArgumentException ex) {
                logger.warn("P3 bind rejected: invalid security label reason={}", ex.getMessage());
                return "ERR code=security-policy detail=" + ex.getMessage();
            }
        }

        logger.info(
            "P3 bind effective channel sender={} requested-channel={} resolved-channel={}",
            canonicalSender,
            requestedChannel,
            effectiveChannel
        );

        final AMHSChannel channel;
        try {
            channel = channelService.requireEnabledChannel(effectiveChannel);
        } catch (IllegalArgumentException ex) {
            logger.warn(
                "P3 bind rejected: channel policy failure channel={} reason={}",
                effectiveChannel,
                ex.getMessage()
            );
            return "ERR code=channel-policy detail=" + ex.getMessage();
        }

        state.bound = true;
        state.username = effectiveIdentity;
        state.senderOrAddress = canonicalSender;
        state.channelName = channel.getName();
        state.lastReadReportId = null;

        logger.info(
            "P3 bind accepted sender={} authenticated-identity={} channel={}",
            state.senderOrAddress,
            state.username,
            state.channelName
        );
        return "OK code=bind-accepted sender=" + state.senderOrAddress + " channel=" + state.channelName;
    }

    private String submit(SessionState state, Map<String, String> attributes) {
        if (!state.bound) {
            logger.warn("P3 submit rejected: submit before bind");
            return "ERR code=association detail=Submit received before bind";
        }

        String recipientAddress = attributes.getOrDefault("recipient", "");
        String body = attributes.getOrDefault("body", "");
        String subject = attributes.getOrDefault("subject", null);

        if (!StringUtils.hasText(recipientAddress)) {
            logger.warn(
                "P3 submit rejected: missing recipient sender={} channel={}",
                state.senderOrAddress,
                state.channelName
            );
            return "ERR code=invalid-or-address detail=Missing recipient address";
        }

        if (!StringUtils.hasText(body)) {
            logger.warn(
                "P3 submit rejected: empty body sender={} channel={}",
                state.senderOrAddress,
                state.channelName
            );
            return "ERR code=invalid-message detail=Body cannot be empty";
        }

        ORAddress sender = ORAddress.parse(state.senderOrAddress);

        final ORAddress recipient;
        try {
            recipient = ORAddress.parse(recipientAddress);
            complianceValidator.validateIcaoOrAddress(recipient.toCanonicalString(), "recipient");
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 submit rejected: invalid recipient reason={}", ex.getMessage());
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
        }

        if (relayRoutingService.hasRoutesConfigured()
            && relayRoutingService.findNextHop(new AMHSMessageEnvelope(recipient, ""), 0).isEmpty()) {
            logger.warn(
                "P3 submit rejected: no route for recipient={} channel={}",
                recipient.toCanonicalString(),
                state.channelName
            );
            return "ERR code=routing-policy detail=No route found for recipient";
        }

        String submissionId = deterministicSubmissionId(
            state.senderOrAddress,
            recipient.toCanonicalString(),
            body,
            subject == null ? "" : subject
        );

        X400MessageRequest request = new X400MessageRequest(
            submissionId,
            body,
            subject,
            null,
            null,
            null,
            null,
            defaultProtocolIndex,
            defaultProtocolAddress,
            defaultServerAddress,
            sender.get("CN"),
            sender.get("OU1"),
            sender.get("OU2"),
            sender.get("OU3"),
            sender.get("OU4"),
            sender.get("O"),
            sender.get("PRMD"),
            sender.get("ADMD"),
            sender.get("C"),
            recipient.get("CN"),
            recipient.get("OU1"),
            recipient.get("OU2"),
            recipient.get("OU3"),
            recipient.get("OU4"),
            recipient.get("O"),
            recipient.get("PRMD"),
            recipient.get("ADMD"),
            recipient.get("C"),
            state.channelName,
            state.username,
            null
        );

        AMHSMessage storedMessage = x400MessageService.storeFromP3(request);
        Long storedId = storedMessage.getId();
        if (storedId != null) {
            submissionCorrelationTable.put(submissionId, storedId);
        }

        logger.info(
            "P3 submit accepted sender={} recipient={} channel={} submissionId={} messageId={}",
            state.senderOrAddress,
            recipient.toCanonicalString(),
            state.channelName,
            submissionId,
            storedMessage.getId()
        );

        String publicMessageId = storedMessage.getMessageId();
        if (!StringUtils.hasText(publicMessageId)) {
            publicMessageId = submissionId;
        }

        return "OK code=submitted" + " sender=" + state.senderOrAddress + " submission-id=" + submissionId + " message-id=" + publicMessageId;
    }

    private String retrieveStatus(SessionState state, Map<String, String> attributes) {
        if (!state.bound) {
            logger.warn("P3 status rejected: operation before bind");
            return "ERR code=association detail=Status operation received before bind";
        }

        String submissionId = attributes.getOrDefault("submission-id", "").trim();
        if (!StringUtils.hasText(submissionId)) {
            logger.warn("P3 status rejected: missing submission-id");
            return "ERR code=invalid-command detail=Missing submission-id";
        }

        ParsedNumber waitTimeout = parseNonNegativeLong(
            attributes.get("wait-timeout-ms"),
            defaultStatusWaitTimeoutMs,
            "wait-timeout-ms"
        );
        if (waitTimeout.error() != null) {
            return waitTimeout.error();
        }

        ParsedNumber retryInterval = parseNonNegativeLong(
            attributes.get("retry-interval-ms"),
            defaultStatusRetryIntervalMs,
            "retry-interval-ms"
        );
        if (retryInterval.error() != null) {
            return retryInterval.error();
        }

        long waitTimeoutMs = waitTimeout.value();
        long retryIntervalMs = Math.max(1L, retryInterval.value());
        Instant deadline = Instant.now().plusMillis(Math.max(0L, waitTimeoutMs));

        StatusSnapshot snapshot = loadStatus(submissionId);
        while (snapshot != null
            && snapshot.drStatus.equals("PENDING")
            && waitTimeoutMs > 0
            && Instant.now().isBefore(deadline)) {
            long remainingMs = Math.max(1L, Duration.between(Instant.now(), deadline).toMillis());
            try {
                Thread.sleep(Math.min(retryIntervalMs, remainingMs));
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return "ERR code=interrupted detail=Status wait interrupted";
            }
            snapshot = loadStatus(submissionId);
        }

        if (snapshot == null) {
            return "ERR code=unknown-submission detail=Unknown submission-id";
        }

        StringBuilder response = new StringBuilder("OK code=status")
            .append(" submission-id=").append(submissionId)
            .append(" message-id=").append(snapshot.message.getId())
            .append(" state=").append(snapshot.message.getLifecycleState())
            .append(" dr-status=").append(snapshot.drStatus)
            .append(" ipn-status=").append(snapshot.ipnStatus);

        if (snapshot.message.getNextRetryAt() != null) {
            response.append(" next-retry-at=").append(snapshot.message.getNextRetryAt().toInstant());
        }
        if (snapshot.message.getDrExpirationAt() != null) {
            response.append(" timeout-at=").append(snapshot.message.getDrExpirationAt().toInstant());
        }
        if (snapshot.latestReport != null && StringUtils.hasText(snapshot.latestReport.getX411DiagnosticCode())) {
            response.append(" diagnostic=").append(snapshot.latestReport.getX411DiagnosticCode());
        }
        return response.toString();
    }

    private StatusSnapshot loadStatus(String submissionId) {
        Long internalMessageId = submissionCorrelationTable.get(submissionId);
        Optional<AMHSMessage> maybeMessage = internalMessageId != null
            ? messageRepository.findById(internalMessageId)
            : Optional.empty();

        if (maybeMessage.isEmpty()) {
            maybeMessage = messageRepository.findByMessageId(submissionId);
        }
        if (maybeMessage.isEmpty()) {
            return null;
        }

        AMHSMessage message = maybeMessage.get();
        if (message.getId() != null) {
            submissionCorrelationTable.put(submissionId, message.getId());
        }

        Optional<AMHSDeliveryReport> latestReport = deliveryReportRepository.findByMessage(message).stream()
            .max((left, right) -> left.getGeneratedAt().compareTo(right.getGeneratedAt()));

        String drStatus = latestReport.map(report -> report.getDeliveryStatus().name()).orElse("PENDING");
        String ipnStatus = resolveIpnStatus(message, latestReport.isPresent());
        return new StatusSnapshot(message, latestReport.orElse(null), drStatus, ipnStatus);
    }

    private String resolveIpnStatus(AMHSMessage message, boolean hasReport) {
        if (message.getIpnRequest() == null || message.getIpnRequest() <= 0) {
            return "NOT-REQUESTED";
        }
        if (hasReport || message.getLifecycleState() == AMHSMessageState.REPORTED) {
            return "REPORTED";
        }
        return "PENDING";
    }

    private ParsedNumber parseNonNegativeLong(String maybeNumber, long fallback, String fieldName) {
        if (!StringUtils.hasText(maybeNumber)) {
            return new ParsedNumber(Math.max(0L, fallback), null);
        }
        try {
            long parsed = Long.parseLong(maybeNumber.trim());
            if (parsed < 0L) {
                return new ParsedNumber(0L, "ERR code=invalid-command detail=" + fieldName + " must be >= 0");
            }
            return new ParsedNumber(parsed, null);
        } catch (NumberFormatException ex) {
            return new ParsedNumber(0L, "ERR code=invalid-command detail=Invalid numeric value for " + fieldName);
        }
    }

    private String readMailbox(SessionState state, Map<String, String> attributes, String operationName) {
        if (!state.bound) {
            logger.warn("P3 read rejected: operation before bind");
            return "ERR code=association detail=" + operationName + " operation received before bind";
        }

        String recipient = attributes.getOrDefault("recipient", state.senderOrAddress);
        if (!StringUtils.hasText(recipient)) {
            logger.warn("P3 read rejected: missing recipient");
            return "ERR code=invalid-or-address detail=Missing recipient address";
        }

        try {
            ORAddress parsedRecipient = ORAddress.parse(recipient);
            complianceValidator.validateIcaoOrAddress(parsedRecipient.toCanonicalString(), "recipient");
            recipient = parsedRecipient.toCanonicalString();
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 read rejected: invalid recipient reason={}", ex.getMessage());
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
        }

        ParsedNumber waitTimeout = parseNonNegativeLong(
            attributes.get("wait-timeout-ms"),
            defaultStatusWaitTimeoutMs,
            "wait-timeout-ms"
        );
        if (waitTimeout.error() != null) {
            return waitTimeout.error();
        }

        ParsedNumber retryInterval = parseNonNegativeLong(
            attributes.get("retry-interval-ms"),
            defaultStatusRetryIntervalMs,
            "retry-interval-ms"
        );
        if (retryInterval.error() != null) {
            return retryInterval.error();
        }

        long waitTimeoutMs = waitTimeout.value();
        long retryIntervalMs = Math.max(1L, retryInterval.value());
        Instant deadline = Instant.now().plusMillis(Math.max(0L, waitTimeoutMs));

        AMHSDeliveryReport report = loadNextReport(recipient, state.lastReadReportId);
        while (report == null && waitTimeoutMs > 0 && Instant.now().isBefore(deadline)) {
            long remainingMs = Math.max(1L, Duration.between(Instant.now(), deadline).toMillis());
            try {
                Thread.sleep(Math.min(retryIntervalMs, remainingMs));
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return "ERR code=interrupted detail=" + operationName + " wait interrupted";
            }
            report = loadNextReport(recipient, state.lastReadReportId);
        }

        String operationCode = operationName.equalsIgnoreCase("Report") ? "report" : "read";
        if (report == null) {
            return "OK code=" + operationCode + "-empty recipient=" + recipient;
        }

        state.lastReadReportId = report.getId();
        return "OK code=" + operationCode
            + " report-id=" + report.getId()
            + " message-id=" + report.getMessage().getMessageId()
            + " recipient=" + report.getRecipient()
            + " report-type=" + report.getReportType()
            + " dr-status=" + report.getDeliveryStatus()
            + (StringUtils.hasText(report.getX411DiagnosticCode()) ? " diagnostic=" + report.getX411DiagnosticCode() : "");
    }

    private AMHSDeliveryReport loadNextReport(String recipient, Long afterId) {
        long cursor = afterId == null ? 0L : Math.max(0L, afterId);
        return deliveryReportRepository
            .findByRecipientIgnoreCaseAndIdGreaterThanOrderByIdAsc(recipient, cursor)
            .stream()
            .findFirst()
            .orElse(null);
    }

    private String unbind(SessionState state) {
        if (!state.bound) {
            logger.warn("P3 release rejected: release before bind");
            return "ERR code=association detail=Release received before bind";
        }

        state.bound = false;
        state.username = null;
        state.senderOrAddress = null;
        state.channelName = null;
        state.lastReadReportId = null;
        state.closed = true;

        logger.info("P3 release completed");
        return "OK code=release";
    }

    private ParsedAttributes parseAttributes(String rawAttributes) {
        Map<String, String> attributes = new LinkedHashMap<>();

        for (String token : Arrays.stream(rawAttributes.split(";")).map(String::trim).toList()) {
            if (!StringUtils.hasText(token)) {
                continue;
            }

            String[] kv = token.split("=", 2);
            if (kv.length != 2 || !StringUtils.hasText(kv[0])) {
                return new ParsedAttributes(
                    Map.of(),
                    "ERR code=invalid-command detail=Malformed attribute token '" + token + "'"
                );
            }

            String key = kv[0].trim().toLowerCase();
            if (attributes.containsKey(key)) {
                return new ParsedAttributes(
                    Map.of(),
                    "ERR code=invalid-command detail=Duplicate attribute '" + key + "'"
                );
            }

            attributes.put(key, kv[1].trim());
        }

        return new ParsedAttributes(attributes, null);
    }

    private String validateAttributeNames(String operation, Map<String, String> attributes) {
        if (attributes.isEmpty()) {
            return null;
        }

        Set<String> allowedAttributes = allowedAttributesForOperation(operation);
        if (allowedAttributes == null) {
            return null;
        }

        Set<String> unsupportedAttributes = new HashSet<>();
        for (String key : attributes.keySet()) {
            if (!allowedAttributes.contains(key)) {
                unsupportedAttributes.add(key);
            }
        }

        if (!unsupportedAttributes.isEmpty()) {
            return "ERR code=invalid-command detail=Unsupported attribute(s) for "
                + operation.toLowerCase()
                + ": "
                + String.join(",", unsupportedAttributes);
        }

        return null;
    }

    private Set<String> allowedAttributesForOperation(String operation) {
        return switch (operation) {
            case "BIND" -> Set.of(
                "username",
                "password",
                "sender",
                "channel",
                "security-label",
                "gateway-policy-label",
                "external-profile-claim"
            );
            case "SUBMIT" -> Set.of("recipient", "subject", "body");
            case "RETRIEVE", "STATUS" -> Set.of("submission-id", "wait-timeout-ms", "retry-interval-ms");
            case "REPORT", "READ" -> Set.of("recipient", "wait-timeout-ms", "retry-interval-ms");
            case "UNBIND", "RELEASE", "QUIT" -> Set.of();
            default -> null;
        };
    }

    private Map<String, String> redactSensitiveAttributes(Map<String, String> attributes) {
        Map<String, String> redacted = new LinkedHashMap<>(attributes);
        if (redacted.containsKey("password")) {
            redacted.put("password", "***");
        }
        return redacted;
    }

    private String trimToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    static String deterministicSubmissionId(String sender, String recipient, String body, String subject) {
        String payload = sender + "|" + recipient + "|" + subject + "|" + body;
        return UUID.nameUUIDFromBytes(payload.getBytes(StandardCharsets.UTF_8)).toString();
    }

    public static final class SessionState {
        private boolean bound;
        private String username;
        private String senderOrAddress;
        private String channelName;
        private boolean closed;
        private Long lastReadReportId;

        public boolean isClosed() {
            return closed;
        }
    }

    private record StatusSnapshot(
        AMHSMessage message,
        AMHSDeliveryReport latestReport,
        String drStatus,
        String ipnStatus
    ) {
    }

    private record ParsedNumber(long value, String error) {
    }

    private record ParsedAttributes(Map<String, String> attributes, String error) {
    }
}