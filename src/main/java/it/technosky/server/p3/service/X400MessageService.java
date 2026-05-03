package it.technosky.server.p3.service;

import java.util.Date;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.address.X400AddressBuilder;
import it.technosky.server.p3.channel.X400MessageRequest;
import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSPriority;
import it.technosky.server.p3.domain.AMHSProfile;

@Service
public class X400MessageService {

    private final MTAService mtaService;
    private final X400AddressBuilder addressBuilder;

    public static final String DEFAULT_CHANNEL_NAME = "ATFM";

    public X400MessageService(MTAService mtaService, X400AddressBuilder addressBuilder) {
        this.mtaService = mtaService;
        this.addressBuilder = addressBuilder;
    }

    public AMHSMessage storeFromP3(X400MessageRequest request) {
        String senderOrAddress = addressBuilder.buildOrAddress(
            request.p3CommonName(),
            request.p3OrganizationUnit(),
            request.p3OrganizationName(),
            request.p3PrivateManagementDomain(),
            request.p3AdministrationManagementDomain(),
            request.p3CountryName(),
            request.p3OrganizationUnit2(),
            request.p3OrganizationUnit3(),
            request.p3OrganizationUnit4()
        );

        String recipientOrAddress = addressBuilder.buildOrAddress(
            request.p3CommonNameRecipient(),
            request.p3OrganizationUnitRecipient(),
            request.p3OrganizationNameRecipient(),
            request.p3PrivateManagementDomainRecipient(),
            request.p3AdministrationManagementDomainRecipient(),
            request.p3CountryNameRecipient(),
            request.p3OrganizationUnit2Recipient(),
            request.p3OrganizationUnit3Recipient(),
            request.p3OrganizationUnit4Recipient()
        );

        String presentationAddress = addressBuilder.buildPresentationAddress(
            request.p3ProtocolIndex(),
            request.p3ProtocolAddress(),
            request.p3ServerAddress()
        );

        return mtaService.storeX400Message(
            senderOrAddress,
            recipientOrAddress,
            request.body(),
            request.messageId(),
            AMHSProfile.P3,
            request.priority() == null ? AMHSPriority.GG : request.priority(),
            request.p3Subject(),
            StringUtils.hasText(request.channel()) ? request.channel() : DEFAULT_CHANNEL_NAME,
            request.certificateCn(),
            request.certificateOu(),
            new Date(),
            senderOrAddress,
            recipientOrAddress,
            presentationAddress,
            request.ipnRequest(),
            request.deliveryReport(),
            request.timeoutDr(),
            null,
            null,
            null,
            null
        );
    }
}
