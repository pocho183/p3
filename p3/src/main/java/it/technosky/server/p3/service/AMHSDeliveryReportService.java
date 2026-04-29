package it.technosky.server.p3.service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import it.technosky.server.p3.domain.AMHSDeliveryReport;
import it.technosky.server.p3.domain.AMHSDeliveryStatus;
import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSMessageState;
import it.technosky.server.p3.domain.AMHSProfile;
import it.technosky.server.p3.domain.AMHSReportType;
import it.technosky.server.p3.repository.AMHSDeliveryReportRepository;
import it.technosky.server.p3.repository.AMHSMessageRepository;
import it.technosky.server.p3.x411.X411DiagnosticMapper;

@Service
public class AMHSDeliveryReportService {

    private final AMHSDeliveryReportRepository deliveryReportRepository;
    private final AMHSMessageRepository messageRepository;
    private final AMHSMessageStateMachine stateMachine;
    private final X411DiagnosticMapper diagnosticMapper;
    private final X411DeliveryReportApduCodec reportApduCodec;

    private static final int BASIC_PROFILE_MAX_RETURN_CONTENT_OCTETS = 2048;
    private static final int EXTENDED_PROFILE_MAX_RETURN_CONTENT_OCTETS = 8192;

    public AMHSDeliveryReportService(
        AMHSDeliveryReportRepository deliveryReportRepository,
        AMHSMessageRepository messageRepository,
        AMHSMessageStateMachine stateMachine,
        X411DiagnosticMapper diagnosticMapper
    ) {
        this.deliveryReportRepository = deliveryReportRepository;
        this.messageRepository = messageRepository;
        this.stateMachine = stateMachine;
        this.diagnosticMapper = diagnosticMapper;
        this.reportApduCodec = new X411DeliveryReportApduCodec();
    }

    public void setReportExpiration(AMHSMessage message) {
        if (message.getTimeoutDr() != null && message.getTimeoutDr() > 0) {
            message.setDrExpirationAt(Date.from(Instant.now().plusSeconds(message.getTimeoutDr())));
        }
    }

    public void createDeliveryReport(AMHSMessage message) {
        AMHSDeliveryReport report = buildReport(
            message,
            message.getRecipient(),
            AMHSReportType.DR,
            AMHSDeliveryStatus.DELIVERED,
            "X411:0",
            null,
            null,
            null
        );
        deliveryReportRepository.save(report);
    }

    public Optional<AMHSMessage> resolveByMtsIdentifier(String mtsIdentifier) {
        if (mtsIdentifier == null || mtsIdentifier.isBlank()) {
            return Optional.empty();
        }
        return messageRepository.findByMtsIdentifier(mtsIdentifier.trim());
    }

    public void createNonDeliveryReport(AMHSMessage message, String reason, String diagnosticCode, AMHSDeliveryStatus status) {
        X411DeliveryReportApduCodec.NonDeliveryReportApdu apdu = new X411DeliveryReportApduCodec.NonDeliveryReportApdu(
            message.getMtsIdentifier() == null ? message.getMessageId() : message.getMtsIdentifier(),
            shouldReturnContent(message),
            List.of(X411DeliveryReportApduCodec.ReportedRecipientInfo.from(message.getRecipient(), status, diagnosticCode)),
            reason
        );
        byte[] rawNdrApdu = reportApduCodec.encodeNonDeliveryReport(apdu);
        X411DeliveryReportApduCodec.ValidationResult validationResult = reportApduCodec.validateEncodedNonDeliveryReport(rawNdrApdu);
        createNonDeliveryReportForRecipient(message, message.getRecipient(), reason, diagnosticCode, status, rawNdrApdu, validationResult);
    }

    private void createNonDeliveryReportForRecipient(
        AMHSMessage message,
        String recipient,
        String reason,
        String diagnosticCode,
        AMHSDeliveryStatus status,
        byte[] rawNdrApdu,
        X411DeliveryReportApduCodec.ValidationResult validationResult
    ) {
        AMHSDeliveryReport report = buildReport(
            message,
            recipient,
            AMHSReportType.NDR,
            status,
            diagnosticCode,
            reason,
            rawNdrApdu,
            validationResult
        );
        deliveryReportRepository.save(report);
    }

    @Scheduled(fixedDelayString = "${amhs.dr.expiration-check-ms:30000}")
    public void expirePendingMessages() {
        Date now = new Date();
        List<AMHSMessage> pending = messageRepository.findByLifecycleStateIn(List.of(
            AMHSMessageState.SUBMITTED,
            AMHSMessageState.TRANSFERRED,
            AMHSMessageState.DEFERRED
        ));

        for (AMHSMessage message : pending) {
            if (message.getDrExpirationAt() == null || !message.getDrExpirationAt().before(now)) {
                continue;
            }
            stateMachine.transition(message, AMHSMessageState.EXPIRED);
            createNonDeliveryReport(message, "transfer-timeout", "X411:16", AMHSDeliveryStatus.EXPIRED);
            stateMachine.transition(message, AMHSMessageState.REPORTED);
            messageRepository.save(message);
        }
    }

    private AMHSDeliveryReport buildReport(
        AMHSMessage message,
        String recipient,
        AMHSReportType reportType,
        AMHSDeliveryStatus status,
        String diagnosticCode,
        String reason,
        byte[] rawNdrApdu,
        X411DeliveryReportApduCodec.ValidationResult validationResult
    ) {
        AMHSDeliveryReport report = new AMHSDeliveryReport();
        report.setMessage(message);
        report.setRecipient(recipient == null || recipient.isBlank() ? message.getRecipient() : recipient);
        report.setReportType(reportType);
        report.setDeliveryStatus(status);
        report.setX411DiagnosticCode(diagnosticCode);
        report.setNonDeliveryReason(reason);
        report.setReturnOfContent(shouldReturnContent(message));
        report.setExpiresAt(message.getDrExpirationAt());
        report.setRelatedMtsIdentifier(message.getMtsIdentifier());
        report.setCorrelationToken(buildCorrelationToken(message));
        if (reportType == AMHSReportType.NDR) {
            report.setNdrApduRawBer(rawNdrApdu);
            if (validationResult != null) {
                report.setNdrApduTagClass(validationResult.tagClass());
                report.setNdrApduTagNumber(validationResult.tagNumber());
            }
        }
        return report;
    }

    private boolean shouldReturnContent(AMHSMessage message) {
        String deliveryReport = message.getDeliveryReport() == null ? "" : message.getDeliveryReport().trim().toLowerCase();
        if (deliveryReport.equals("headers")) {
            return false;
        }

        int bodySize = message.getBody() == null ? 0 : message.getBody().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        int sizeLimit = message.getProfile() == AMHSProfile.P3
            ? BASIC_PROFILE_MAX_RETURN_CONTENT_OCTETS
            : EXTENDED_PROFILE_MAX_RETURN_CONTENT_OCTETS;
        boolean withinLimit = bodySize <= sizeLimit;

        if (deliveryReport.equals("full") || deliveryReport.equals("content-return-requested")) {
            return withinLimit;
        }
        if (message.getIpnRequest() != null && message.getIpnRequest() > 0) {
            return message.getProfile() != AMHSProfile.P3 && withinLimit;
        }
        return false;
    }

    private String buildCorrelationToken(AMHSMessage message) {
        String msgId = message.getMessageId() == null ? "" : message.getMessageId().trim();
        String mts = message.getMtsIdentifier() == null ? "" : message.getMtsIdentifier().trim();
        if (!msgId.isEmpty() && !mts.isEmpty()) {
            return msgId + "::" + mts;
        }
        if (!msgId.isEmpty()) {
            return "MSG::" + msgId;
        }
        if (!mts.isEmpty()) {
            return "MTS::" + mts;
        }
        return null;
    }
}
