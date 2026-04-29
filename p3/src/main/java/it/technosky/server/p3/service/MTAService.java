package it.technosky.server.p3.service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.channel.AMHSChannelService;
import it.technosky.server.p3.compliance.AMHSComplianceValidator;
import it.technosky.server.p3.domain.AMHSChannel;
import it.technosky.server.p3.domain.AMHSDeliveryStatus;
import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSMessageState;
import it.technosky.server.p3.domain.AMHSPriority;
import it.technosky.server.p3.domain.AMHSProfile;
import it.technosky.server.p3.repository.AMHSMessageRepository;
import it.technosky.server.p3.x411.X411DiagnosticMapper;

@Service
public class MTAService {

    private static final Logger logger = LoggerFactory.getLogger(MTAService.class);

    private final AMHSMessageRepository amhsMessagesRepository;
    private final AMHSComplianceValidator complianceValidator;
    private final AMHSChannelService channelService;
    private final AMHSMessageStateMachine stateMachine;
    private final AMHSDeliveryReportService deliveryReportService;
    private final boolean databaseEnabled;
    private final X411DiagnosticMapper diagnosticMapper;

    public MTAService(
        AMHSMessageRepository amhsMessagesRepository,
        AMHSComplianceValidator complianceValidator,
        AMHSChannelService channelService,
        AMHSMessageStateMachine stateMachine,
        AMHSDeliveryReportService deliveryReportService,
        X411DiagnosticMapper diagnosticMapper,
        @Value("${amhs.database.enabled:true}") boolean databaseEnabled
    ) {
        this.amhsMessagesRepository = amhsMessagesRepository;
        this.complianceValidator = complianceValidator;
        this.channelService = channelService;
        this.stateMachine = stateMachine;
        this.deliveryReportService = deliveryReportService;
        this.databaseEnabled = databaseEnabled;
        this.diagnosticMapper = diagnosticMapper;
    }

    public AMHSMessage storeMessage(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channelName,
        String certificateCn,
        String certificateOu,
        Date filingTime
    ) {
        AMHSMessage message = buildBaseMessage(from, to, body, messageId, profile, priority, subject, channelName, certificateCn, certificateOu, filingTime);
        if (!databaseEnabled) {
            logReceivedMessage(message);
            return message;
        }

        return validatePersistAndReport(message, from, to, body, profile, channelName, certificateCn, certificateOu);
    }

    public AMHSMessage storeX400Message(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channelName,
        String certificateCn,
        String certificateOu,
        Date filingTime,
        String senderOrAddress,
        String recipientOrAddress,
        String presentationAddress,
        Integer ipnRequest,
        String deliveryReport,
        Integer timeoutDr,
        String mtsIdentifier,
        String transferContentTypeOid,
        String transferTrace,
        String perRecipientFields
    ) {
        AMHSMessage message = buildBaseMessage(from, to, body, messageId, profile, priority, subject, channelName, certificateCn, certificateOu, filingTime);
        message.setSenderOrAddress(normalize(senderOrAddress));
        message.setRecipientOrAddress(normalize(recipientOrAddress));
        message.setPresentationAddress(normalize(presentationAddress));
        message.setIpnRequest(ipnRequest);
        message.setDeliveryReport(normalize(deliveryReport));
        message.setTimeoutDr(timeoutDr);
        message.setMtsIdentifier(normalize(mtsIdentifier));
        message.setTransferContentTypeOid(normalize(transferContentTypeOid));
        message.setTransferTrace(normalize(transferTrace));
        message.setPerRecipientFields(normalize(perRecipientFields));

        if (!databaseEnabled) {
            logReceivedMessage(message);
            return message;
        }

        return validatePersistAndReport(message, from, to, body, profile, channelName, certificateCn, certificateOu);
    }

    public List<AMHSMessage> findAll() {
        return amhsMessagesRepository.findAll();
    }

    public List<AMHSMessage> findByFilters(String channelName, AMHSProfile profile) {
        if (StringUtils.hasText(channelName) && profile != null) {
            return amhsMessagesRepository.findByChannelNameIgnoreCaseAndProfile(channelName.trim(), profile);
        }
        if (StringUtils.hasText(channelName)) {
            return amhsMessagesRepository.findByChannelNameIgnoreCase(channelName.trim());
        }
        if (profile != null) {
            return amhsMessagesRepository.findByProfile(profile);
        }
        return amhsMessagesRepository.findAll();
    }

    private AMHSMessage buildBaseMessage(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channelName,
        String certificateCn,
        String certificateOu,
        Date filingTime
    ) {
        AMHSMessage message = new AMHSMessage();
        message.setMessageId(resolveMessageId(messageId));
        message.setSender(normalizeUpper(from));
        message.setRecipient(normalizeUpper(to));
        message.setBody(normalize(body));
        message.setProfile(profile);
        message.setPriority(priority == null ? AMHSPriority.GG : priority);
        message.setSubject(normalize(subject));
        message.setChannelName(normalize(channelName));
        message.setCertificateCn(normalize(certificateCn));
        message.setCertificateOu(normalize(certificateOu));
        message.setFilingTime(filingTime == null ? new Date() : filingTime);
        stateMachine.initialize(message);
        return message;
    }

    private AMHSMessage validatePersistAndReport(
        AMHSMessage message,
        String from,
        String to,
        String body,
        AMHSProfile profile,
        String channelName,
        String certificateCn,
        String certificateOu
    ) {
        try {
            complianceValidator.validate(from, to, body, profile);
            AMHSChannel channel = channelService.requireEnabledChannel(channelName);
            complianceValidator.validateCertificateIdentity(channel, certificateCn, certificateOu);
            complianceValidator.validateOrAddressBinding(from, certificateCn, certificateOu);
            message.setChannelName(channel.getName());

            stateMachine.transition(message, AMHSMessageState.TRANSFERRED);
            deliveryReportService.setReportExpiration(message);

            AMHSMessage saved = amhsMessagesRepository.save(message);
            stateMachine.transition(saved, AMHSMessageState.DELIVERED);
            AMHSMessage delivered = amhsMessagesRepository.save(saved);

            deliveryReportService.createDeliveryReport(delivered);
            stateMachine.transition(delivered, AMHSMessageState.REPORTED);
            return amhsMessagesRepository.save(delivered);
        } catch (RuntimeException ex) {
            if (message.getLifecycleState() != AMHSMessageState.REPORTED) {
                stateMachine.transition(message, AMHSMessageState.FAILED);
                AMHSMessage failed = amhsMessagesRepository.save(message);
                String reason = "validation-or-routing-failure";
                String diagnosticCode = diagnosticMapper.map(reason, ex.getMessage());
                deliveryReportService.createNonDeliveryReport(failed, reason, diagnosticCode, AMHSDeliveryStatus.FAILED);
                stateMachine.transition(failed, AMHSMessageState.REPORTED);
                amhsMessagesRepository.save(failed);
            }
            throw ex;
        }
    }

    private void logReceivedMessage(AMHSMessage message) {
        logger.info(
            "Database disabled. Received AMHS message [messageId={}, from={}, to={}, channel={}, profile={}, priority={}, subject={}, body={}]",
            message.getMessageId(),
            message.getSender(),
            message.getRecipient(),
            message.getChannelName(),
            message.getProfile(),
            message.getPriority(),
            message.getSubject(),
            message.getBody()
        );
    }

    private String resolveMessageId(String messageId) {
        return StringUtils.hasText(messageId) ? messageId.trim() : UUID.randomUUID().toString();
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String normalizeUpper(String value) {
        String normalized = normalize(value);
        return normalized == null ? null : normalized.toUpperCase();
    }
}
