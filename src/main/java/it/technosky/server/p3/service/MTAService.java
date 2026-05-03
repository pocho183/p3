package it.technosky.server.p3.service;

import java.util.Date;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.compliance.AMHSComplianceValidator;
import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSPriority;
import it.technosky.server.p3.domain.AMHSProfile;
import it.technosky.server.p3.x411.X411DiagnosticMapper;

@Service
public class MTAService {

    private static final Logger logger = LoggerFactory.getLogger(MTAService.class);

    private final AMHSMessageStateMachine stateMachine;


    public MTAService(
        AMHSComplianceValidator complianceValidator,
        AMHSMessageStateMachine stateMachine,
        X411DiagnosticMapper diagnosticMapper
    ) {
        this.stateMachine = stateMachine;
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

        return message;
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

        return message;
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
