package it.technosky.server.p3.acse;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Component;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;


@Component
public class AcseAssociationProtocol {

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int AARQ_TAG = 0;
    private static final int AARE_TAG = 1;
    private static final int RLRQ_TAG = 2;
    private static final int RLRE_TAG = 3;
    private static final int ABRT_TAG = 4;

    private static final String DEFAULT_TRANSFER_SYNTAX_OID = "2.1.1";

    public byte[] encode(AcseModels.AcseApdu apdu) {
        if (apdu instanceof AcseModels.AARQApdu aarq) {
            return encodeAarq(aarq);
        }
        if (apdu instanceof AcseModels.AAREApdu aare) {
            return encodeAare(aare);
        }
        if (apdu instanceof AcseModels.RLRQApdu rlrq) {
            return encodeRlrq(rlrq);
        }
        if (apdu instanceof AcseModels.RLREApdu rlre) {
            return encodeRlre(rlre);
        }
        if (apdu instanceof AcseModels.ABRTApdu abrt) {
            return encodeAbrt(abrt);
        }
        throw new IllegalArgumentException("Unsupported ACSE APDU type: " + apdu.getClass().getSimpleName());
    }

    public AcseModels.AcseApdu decode(byte[] payload) {
        BerTlv apdu = BerCodec.decodeSingle(payload);
        if (apdu.tagClass() != TAG_CLASS_APPLICATION || !apdu.constructed()) {
            throw new IllegalArgumentException("ACSE APDU must use APPLICATION class constructed encoding");
        }

        return switch (apdu.tagNumber()) {
            case AARQ_TAG -> decodeAarq(apdu.value());
            case AARE_TAG -> decodeAare(apdu.value());
            case RLRQ_TAG -> decodeRlrq(apdu.value());
            case RLRE_TAG -> decodeRlre(apdu.value());
            case ABRT_TAG -> decodeAbrt(apdu.value());
            default -> throw new IllegalArgumentException(
                "Unsupported ACSE APDU application tag [" + apdu.tagNumber() + "]"
            );
        };
    }

    private byte[] encodeAarq(AcseModels.AARQApdu aarq) {
        byte[] payload = concat(
            encodeBitString(0, 0x80),
            encodeOid(1, aarq.applicationContextName()),

            aarq.calledApTitle()
                .map(v -> encodeApTitleField(2, v))
                .orElse(new byte[0]),

            aarq.calledAeQualifier()
                .map(v -> encodeSmallInteger(3, v.value()))
                .orElseGet(() ->
                    aarq.calledAeTitle()
                        .map(v -> encodeGraphicString(3, v))
                        .orElse(new byte[0])
                ),

            aarq.callingApTitle()
                .map(v -> encodeApTitleField(6, v))
                .orElse(new byte[0]),

            aarq.callingAeQualifier()
                .map(v -> encodeSmallInteger(7, v.value()))
                .orElseGet(() ->
                    aarq.callingAeTitle()
                        .map(v -> encodeGraphicString(7, v))
                        .orElse(new byte[0])
                ),

            aarq.authenticationValue()
                .map(v -> encodeOctetString(12, v))
                .orElse(new byte[0]),

            aarq.presentationContexts().isEmpty()
                ? new byte[0]
                : encodePresentationContextDefinitionList(29, aarq.presentationContexts()),

            aarq.userInformation()
                .map(v -> encodeUserInformation(30, v))
                .orElse(new byte[0])
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, AARQ_TAG, 0, payload.length, payload)
        );
    }

    private byte[] encodeAare(AcseModels.AAREApdu aare) {
        int result = aare.accepted() ? 0 : 1;

        byte[] payload = concat(
            aare.applicationContextName().map(v -> encodeOid(1, v)).orElse(new byte[0]),
            encodeAssociateResultExplicit(2, result),
            aare.resultSourceDiagnostic()
                .map(this::encodeResultSourceDiagnosticExplicit)
                .orElse(new byte[0]),
            aare.respondingApTitle()
                .map(v -> encodeApTitleField(4, v))
                .orElse(new byte[0]),
            aare.respondingAeQualifier()
                .map(v -> encodeSmallIntegerExplicit(5, v.value()))
                .orElseGet(() ->
                    aare.respondingAeTitle()
                        .map(v -> encodeGraphicString(5, v))
                        .orElse(new byte[0])
                ),
            encodeAarePresentationNegotiation(aare),
            aare.userInformation().map(v -> encodeUserInformation(30, v)).orElse(new byte[0])
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, AARE_TAG, 0, payload.length, payload)
        );
    }

    private byte[] encodeApTitleField(int tagNumber, AcseModels.ApTitle apTitle) {
        if (apTitle == null) {
            return new byte[0];
        }

        if (apTitle.isOidForm()) {
            return encodeOid(tagNumber, apTitle.objectIdentifier().orElseThrow());
        }

        if (apTitle.isRawBerForm()) {
            byte[] raw = apTitle.rawBerBytes();
            return BerCodec.encode(
                new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, raw.length, raw)
            );
        }

        throw new IllegalArgumentException("ACSE AP-title has no usable encoding");
    }

    private byte[] encodeAssociateResultExplicit(int tagNumber, int value) {
        if (value < 0) {
            throw new IllegalArgumentException("ACSE associate result must be non-negative");
        }

        byte[] integerValue = integerBytes(value);
        byte[] integerTlv = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, integerValue.length, integerValue)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, integerTlv.length, integerTlv)
        );
    }

    private byte[] encodeSmallIntegerExplicit(int tagNumber, int value) {
        if (value < 0) {
            throw new IllegalArgumentException("ACSE integer field must be non-negative");
        }

        byte[] integerValue = integerBytes(value);
        byte[] integerTlv = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, integerValue.length, integerValue)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, integerTlv.length, integerTlv)
        );
    }

    private byte[] encodeResultSourceDiagnosticExplicit(AcseModels.ResultSourceDiagnostic rsd) {
        int source = rsd.source();
        int diagnostic = rsd.diagnostic();

        int choiceTag;
        if (source == 1) {
            choiceTag = 1;
        } else if (source == 2) {
            choiceTag = 2;
        } else {
            throw new IllegalArgumentException("Unsupported ACSE result-source-diagnostic source: " + source);
        }

        byte[] diagnosticValue = integerBytes(diagnostic);
        byte[] diagnosticInteger = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, diagnosticValue.length, diagnosticValue)
        );

        byte[] choice = BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, choiceTag, 0, diagnosticInteger.length, diagnosticInteger)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, 3, 0, choice.length, choice)
        );
    }

    private AcseModels.AARQApdu decodeAarq(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);

        String appCtx = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
            .map(this::decodeOid)
            .orElseThrow(() -> new IllegalArgumentException("AARQ is missing application-context-name [1]"));

        Optional<String> calledAe = Optional.empty();
        Optional<AcseModels.AeQualifier> calledQualifier = Optional.empty();
        Optional<BerTlv> calledField = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 3);
        if (calledField.isPresent()) {
            if (isWrappedDirectoryString(calledField.get())) {
                calledAe = Optional.of(decodeDirectoryString(calledField.get()));
            } else {
                calledQualifier = Optional.of(
                    new AcseModels.AeQualifier(decodeNonNegativeInteger(calledField.get()))
                );
            }
        }

        Optional<String> callingAe = Optional.empty();
        Optional<AcseModels.AeQualifier> callingQualifier = Optional.empty();
        Optional<BerTlv> callingField = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 7);
        if (callingField.isPresent()) {
            if (isWrappedDirectoryString(callingField.get())) {
                callingAe = Optional.of(decodeDirectoryString(callingField.get()));
            } else {
                callingQualifier = Optional.of(
                    new AcseModels.AeQualifier(decodeNonNegativeInteger(callingField.get()))
                );
            }
        }

        Optional<AcseModels.ApTitle> calledApTitle = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 2)
            .map(v -> new AcseModels.ApTitle(decodeOid(v)));

        Optional<AcseModels.ApTitle> callingApTitle = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 6)
            .map(v -> new AcseModels.ApTitle(decodeOid(v)));

        Optional<byte[]> authValue = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 12)
            .map(this::decodeAuthenticationValue);

        Optional<byte[]> userInformation = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 30)
            .map(this::decodeUserInformation);

        PresentationContextParseResult presentationContexts = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 29)
            .map(this::decodePresentationContexts)
            .orElseGet(PresentationContextParseResult::empty);

        return new AcseModels.AARQApdu(
            appCtx,
            callingAe,
            calledAe,
            callingApTitle,
            callingQualifier,
            calledApTitle,
            calledQualifier,
            authValue,
            userInformation,
            presentationContexts.abstractSyntaxOids(),
            presentationContexts.proposedContexts()
        );
    }

    private AcseModels.AAREApdu decodeAare(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);

        int result = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 2)
            .map(this::decodeSmallInteger)
            .orElseThrow(() -> new IllegalArgumentException("AARE is missing result [2]"));

        Optional<AcseModels.ResultSourceDiagnostic> rsd =
            BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 3)
                .map(this::decodeResultSourceDiagnostic);

        Optional<String> diagnostic =
            BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 10)
                .map(this::decodeGraphicString);

        if (diagnostic.isEmpty() && rsd.isPresent()) {
            diagnostic = Optional.of("source=" + rsd.get().source() + ",diag=" + rsd.get().diagnostic());
        }

        Optional<AcseModels.ApTitle> respondingApTitle =
        	    BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 4)
        	        .map(this::decodeApTitleField);

        Optional<String> respondingAeTitle = Optional.empty();
        Optional<AcseModels.AeQualifier> respondingAeQualifier = Optional.empty();

        Optional<BerTlv> respondingField = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 5);
        if (respondingField.isPresent()) {
            if (isWrappedDirectoryString(respondingField.get())) {
                respondingAeTitle = Optional.of(decodeDirectoryString(respondingField.get()));
            } else {
                respondingAeQualifier = Optional.of(
                    new AcseModels.AeQualifier(decodeNonNegativeInteger(respondingField.get()))
                );
            }
        }

        Optional<byte[]> userInfo =
            BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 30)
                .map(this::decodeUserInformation);

        PresentationContextParseResult presentationContexts =
            BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 29)
                .map(this::decodePresentationContexts)
                .orElseGet(PresentationContextParseResult::empty);

        Optional<String> appCtx =
            BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
                .map(this::decodeOid);

        return new AcseModels.AAREApdu(
            appCtx,
            result == 0,
            diagnostic,
            rsd,
            respondingApTitle,
            respondingAeQualifier,
            respondingAeTitle,
            userInfo,
            presentationContexts.abstractSyntaxOids(),
            presentationContexts.acceptedContextIdentifiers()
        );
    }
    
    private AcseModels.ApTitle decodeApTitleField(BerTlv wrapped) {
        if (wrapped == null || wrapped.tagClass() != TAG_CLASS_CONTEXT || !wrapped.constructed()) {
            throw new IllegalArgumentException("ACSE AP-title must be explicit context-specific");
        }

        byte[] inner = wrapped.value();
        if (inner.length == 0) {
            throw new IllegalArgumentException("ACSE AP-title is empty");
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(inner);
            if (tlv.isUniversal() && tlv.tagNumber() == 6) {
                return AcseModels.ApTitle.fromOid(decodeOid(wrapped));
            }
        } catch (RuntimeException ignored) {
        }

        return AcseModels.ApTitle.fromRawBer(inner);
    }

    private byte[] encodeRlrq(AcseModels.RLRQApdu rlrq) {
        byte[] payload = rlrq.reason().map(v -> encodeGraphicString(0, v)).orElse(new byte[0]);
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, RLRQ_TAG, 0, payload.length, payload)
        );
    }

    private AcseModels.RLRQApdu decodeRlrq(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        Optional<String> reason = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeGraphicString);
        return new AcseModels.RLRQApdu(reason);
    }

    private byte[] encodeRlre(AcseModels.RLREApdu rlre) {
        byte[] payload = encodeResult(0, rlre.normal() ? 0 : 1);
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, RLRE_TAG, 0, payload.length, payload)
        );
    }

    private AcseModels.RLREApdu decodeRlre(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        int result = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeSmallInteger)
            .orElse(0);
        return new AcseModels.RLREApdu(result == 0);
    }

    private byte[] encodeAbrt(AcseModels.ABRTApdu abrt) {
        byte[] payload = concat(
            encodeGraphicString(0, abrt.source()),
            abrt.diagnostic().map(v -> encodeGraphicString(1, v)).orElse(new byte[0])
        );
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, ABRT_TAG, 0, payload.length, payload)
        );
    }

    private AcseModels.ABRTApdu decodeAbrt(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        String source = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeGraphicString)
            .orElse("acse-service-user");
        Optional<String> diagnostic = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
            .map(this::decodeGraphicString);
        return new AcseModels.ABRTApdu(source, diagnostic);
    }

    private byte[] encodeGraphicString(int tagNumber, String text) {
        byte[] textBytes = text.trim().getBytes(StandardCharsets.US_ASCII);
        byte[] primitive = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 25, 0, textBytes.length, textBytes)
        );
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, primitive.length, primitive)
        );
    }

    private String decodeGraphicString(BerTlv wrapped) {
        BerTlv graphicString = BerCodec.decodeSingle(wrapped.value());
        if (!graphicString.isUniversal() || graphicString.tagNumber() != 25) {
            throw new IllegalArgumentException(
                "ACSE expected GraphicString inside field [" + wrapped.tagNumber() + "]"
            );
        }
        return new String(graphicString.value(), StandardCharsets.US_ASCII);
    }

    private byte[] encodeOid(int tagNumber, String dottedOid) {
        byte[] oidEncoded = encodeOidValue(dottedOid);
        byte[] oidTlv = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 6, 0, oidEncoded.length, oidEncoded)
        );
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, oidTlv.length, oidTlv)
        );
    }

    private String decodeOid(BerTlv wrappedOid) {
        BerTlv oidTlv = BerCodec.decodeSingle(wrappedOid.value());
        if (!oidTlv.isUniversal() || oidTlv.tagNumber() != 6) {
            throw new IllegalArgumentException(
                "ACSE expected OBJECT IDENTIFIER inside field [" + wrappedOid.tagNumber() + "]"
            );
        }
        return decodeOidValue(oidTlv.value());
    }

    private byte[] encodeBitString(int tagNumber, int bits) {
        byte[] bitString = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 3, 0, 2, new byte[] { 0x00, (byte) bits })
        );
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, bitString.length, bitString)
        );
    }

    private byte[] encodeSmallInteger(int tagNumber, int value) {
        if (value < 0) {
            throw new IllegalArgumentException("ACSE integer/ENUMERATED field must be non-negative");
        }
        byte[] valueBytes = integerBytes(value);
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, false, tagNumber, 0, valueBytes.length, valueBytes)
        );
    }

    private byte[] encodeResult(int tagNumber, int value) {
        if (value < 0) {
            throw new IllegalArgumentException("ACSE result must be non-negative");
        }

        byte[] valueBytes = integerBytes(value);
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, false, tagNumber, 0, valueBytes.length, valueBytes)
        );
    }

    private int decodeSmallInteger(BerTlv encoded) {
        if (encoded.tagClass() == TAG_CLASS_CONTEXT && encoded.constructed()) {
            BerTlv inner = BerCodec.decodeSingle(encoded.value());
            if (inner.tagClass() != TAG_CLASS_UNIVERSAL || inner.tagNumber() != 2) {
                throw new IllegalArgumentException(
                    "ACSE expected INTEGER inside explicit field [" + encoded.tagNumber() + "]"
                );
            }
            return decodeNonNegativeInteger(inner);
        }
        return decodeNonNegativeInteger(encoded);
    }

    private int decodeNonNegativeInteger(BerTlv encoded) {
        if (encoded.value().length == 0 || encoded.value().length > 4) {
            throw new IllegalArgumentException("ACSE integer/ENUMERATED field length is not supported");
        }

        int value = 0;
        for (byte octet : encoded.value()) {
            value = (value << 8) | (octet & 0xFF);
        }

        if ((encoded.value()[0] & 0x80) != 0) {
            throw new IllegalArgumentException("ACSE integer/ENUMERATED field must be non-negative");
        }

        return value;
    }

    private AcseModels.ResultSourceDiagnostic decodeResultSourceDiagnostic(BerTlv wrapped) {
        List<BerTlv> fields = BerCodec.decodeAll(wrapped.value());
        if (fields.size() != 1) {
            throw new IllegalArgumentException(
                "ACSE result-source-diagnostic must contain exactly one CHOICE value"
            );
        }

        BerTlv choice = fields.get(0);
        if (choice.tagClass() != TAG_CLASS_CONTEXT || !choice.constructed()) {
            throw new IllegalArgumentException(
                "ACSE result-source-diagnostic choice must be explicit context-specific"
            );
        }

        int source;
        if (choice.tagNumber() == 1) {
            source = 1;
        } else if (choice.tagNumber() == 2) {
            source = 2;
        } else {
            throw new IllegalArgumentException(
                "Unsupported ACSE result-source-diagnostic choice [" + choice.tagNumber() + "]"
            );
        }

        BerTlv inner = BerCodec.decodeSingle(choice.value());
        if (inner.tagClass() != TAG_CLASS_UNIVERSAL || inner.tagNumber() != 2) {
            throw new IllegalArgumentException(
                "ACSE result-source-diagnostic choice must contain INTEGER"
            );
        }

        int diagnostic = decodeNonNegativeInteger(inner);
        return new AcseModels.ResultSourceDiagnostic(source, diagnostic);
    }

    private byte[] encodeOctetString(int tagNumber, byte[] value) {
        byte[] octetString = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 4, 0, value.length, value)
        );
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, octetString.length, octetString)
        );
    }

    private byte[] decodeAuthenticationValue(BerTlv wrapped) {
        BerTlv authValue = BerCodec.decodeSingle(wrapped.value());
        if (!authValue.isUniversal()) {
            throw new IllegalArgumentException(
                "ACSE authentication-value must be encoded as universal string/bit/octet type"
            );
        }

        return switch (authValue.tagNumber()) {
            case 4 -> authValue.value();
            case 12 -> new String(authValue.value(), StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8);
            case 19, 20, 22, 25, 26 ->
                new String(authValue.value(), StandardCharsets.US_ASCII).getBytes(StandardCharsets.UTF_8);
            case 28, 30 -> decodeUnicodeStringValue(authValue.value());
            case 3 -> decodeBitStringValue(authValue.value());
            default -> throw new IllegalArgumentException(
                "ACSE authentication-value universal tag [" + authValue.tagNumber() + "] is not supported"
            );
        };
    }

    private byte[] decodeUnicodeStringValue(byte[] rawValue) {
        if (rawValue.length % 2 != 0) {
            throw new IllegalArgumentException(
                "ACSE Unicode string authentication-value must contain an even number of octets"
            );
        }
        return new String(rawValue, StandardCharsets.UTF_16BE).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] decodeBitStringValue(byte[] bitStringPayload) {
        if (bitStringPayload.length == 0) {
            throw new IllegalArgumentException("ACSE BIT STRING authentication-value cannot be empty");
        }

        int unusedBits = bitStringPayload[0] & 0xFF;
        if (unusedBits != 0) {
            throw new IllegalArgumentException(
                "ACSE BIT STRING authentication-value with non-zero unused bits is not supported"
            );
        }

        byte[] out = new byte[bitStringPayload.length - 1];
        System.arraycopy(bitStringPayload, 1, out, 0, out.length);
        return out;
    }

    private byte[] encodeAarePresentationNegotiation(AcseModels.AAREApdu aare) {
        if (!aare.acceptedPresentationContextIds().isEmpty()) {
            return encodeAcceptedPresentationContextIds(29, aare.acceptedPresentationContextIds());
        }
        if (!aare.presentationContextOids().isEmpty()) {
            return encodePresentationContexts(29, aare.presentationContextOids());
        }
        return new byte[0];
    }

    private byte[] encodePresentationContexts(int tagNumber, List<String> contextOids) {
        List<PresentationContext> contexts = new ArrayList<>();
        int contextIdentifier = 1;

        for (String oid : contextOids) {
            contexts.add(new PresentationContext(contextIdentifier, oid, List.of(DEFAULT_TRANSFER_SYNTAX_OID)));
            contextIdentifier += 2;
        }

        return encodePresentationContextDefinitionList(tagNumber, contexts);
    }

    private byte[] encodePresentationContextDefinitionList(int tagNumber, List<PresentationContext> contexts) {
        List<byte[]> entries = new ArrayList<>();

        for (PresentationContext context : contexts) {
            context.validate();

            byte[] abstractSyntaxValue = encodeOidValue(context.abstractSyntaxOid());
            byte[] abstractSyntax = BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, false, 6, 0, abstractSyntaxValue.length, abstractSyntaxValue)
            );

            List<byte[]> transferSyntaxes = new ArrayList<>();
            for (String transferSyntaxOid : context.transferSyntaxOids()) {
                byte[] tsValue = encodeOidValue(transferSyntaxOid);
                transferSyntaxes.add(
                    BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, false, 6, 0, tsValue.length, tsValue))
                );
            }

            byte[] transferSyntaxListPayload = concat(transferSyntaxes.toArray(new byte[0][]));
            byte[] transferSyntaxList = BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, transferSyntaxListPayload.length, transferSyntaxListPayload)
            );

            byte[] contextIdentifierField = BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { (byte) context.identifier() })
            );

            byte[] payload = concat(contextIdentifierField, abstractSyntax, transferSyntaxList);

            entries.add(
                BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, payload.length, payload))
            );
        }

        byte[] sequence = concat(entries.toArray(new byte[0][]));
        byte[] wrappedSeq = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, sequence.length, sequence)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, wrappedSeq.length, wrappedSeq)
        );
    }

    private byte[] encodeAcceptedPresentationContextIds(int tagNumber, Set<Integer> acceptedContextIds) {
        List<Integer> sortedIds = acceptedContextIds.stream().sorted().toList();
        List<byte[]> items = new ArrayList<>();

        for (Integer id : sortedIds) {
            if (id == null || id <= 0 || id % 2 == 0) {
                throw new IllegalArgumentException(
                    "Accepted presentation-context identifier must be an odd positive integer"
                );
            }
            items.add(
                BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { (byte) (id & 0xFF) }))
            );
        }

        byte[] seqPayload = concat(items.toArray(new byte[0][]));
        byte[] wrappedSeq = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, seqPayload.length, seqPayload)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, wrappedSeq.length, wrappedSeq)
        );
    }

    private PresentationContextParseResult decodePresentationContexts(BerTlv wrapped) {
        BerTlv seq = BerCodec.decodeSingle(wrapped.value());
        if (!seq.isUniversal() || seq.tagNumber() != 16) {
            throw new IllegalArgumentException("ACSE expected SEQUENCE for presentation contexts");
        }

        List<String> oids = new ArrayList<>();
        List<PresentationContext> proposed = new ArrayList<>();
        Set<Integer> accepted = new LinkedHashSet<>();
        Set<Integer> proposedIds = new LinkedHashSet<>();

        for (BerTlv item : BerCodec.decodeAll(seq.value())) {
            if (item.isUniversal() && !item.constructed() && item.tagNumber() == 2 && item.value().length == 1) {
                int id = item.value()[0] & 0xFF;
                if (id <= 0 || id % 2 == 0 || !accepted.add(id)) {
                    throw new IllegalArgumentException(
                        "ACSE presentation context identifier must be unique odd positive integer"
                    );
                }
                continue;
            }

            if (!item.isUniversal() || item.tagNumber() != 16) {
                throw new IllegalArgumentException("ACSE presentation context list item must be a SEQUENCE");
            }

            List<BerTlv> contextFields = BerCodec.decodeAll(item.value());
            if (contextFields.isEmpty()) {
                throw new IllegalArgumentException("ACSE presentation context item cannot be empty");
            }

            if (contextFields.size() == 1) {
                BerTlv oidTlv = contextFields.get(0);
                if (!oidTlv.isUniversal() || oidTlv.tagNumber() != 6) {
                    throw new IllegalArgumentException(
                        "ACSE presentation context item must contain OBJECT IDENTIFIER"
                    );
                }
                oids.add(decodeOidValue(oidTlv.value()));
                continue;
            }

            if (contextFields.size() != 3) {
                throw new IllegalArgumentException(
                    "ACSE presentation context item must contain identifier, abstract syntax and transfer syntax list"
                );
            }

            BerTlv id = contextFields.get(0);
            if (!id.isUniversal() || id.tagNumber() != 2 || id.value().length != 1) {
                throw new IllegalArgumentException(
                    "ACSE presentation context item must start with INTEGER identifier"
                );
            }

            int identifier = id.value()[0] & 0xFF;
            if (!proposedIds.add(identifier)) {
                throw new IllegalArgumentException(
                    "ACSE presentation context identifier must be unique odd positive integer"
                );
            }

            BerTlv abstractSyntaxTlv = contextFields.get(1);
            if (!abstractSyntaxTlv.isUniversal() || abstractSyntaxTlv.tagNumber() != 6) {
                throw new IllegalArgumentException(
                    "ACSE presentation context abstract syntax must be OBJECT IDENTIFIER"
                );
            }

            String abstractSyntaxOid = decodeOidValue(abstractSyntaxTlv.value());
            oids.add(abstractSyntaxOid);

            BerTlv transferSyntaxList = contextFields.get(2);
            if (!transferSyntaxList.isUniversal() || transferSyntaxList.tagNumber() != 16) {
                throw new IllegalArgumentException(
                    "ACSE presentation context transfer syntaxes must be a SEQUENCE"
                );
            }

            List<BerTlv> transferSyntaxes = BerCodec.decodeAll(transferSyntaxList.value());
            if (transferSyntaxes.isEmpty()) {
                throw new IllegalArgumentException(
                    "ACSE presentation context transfer syntax list cannot be empty"
                );
            }

            List<String> transferSyntaxOids = new ArrayList<>();
            for (BerTlv transferSyntax : transferSyntaxes) {
                if (!transferSyntax.isUniversal() || transferSyntax.tagNumber() != 6) {
                    throw new IllegalArgumentException("ACSE transfer syntax must be OBJECT IDENTIFIER");
                }
                transferSyntaxOids.add(decodeOidValue(transferSyntax.value()));
            }

            PresentationContext context =
                new PresentationContext(identifier, abstractSyntaxOid, transferSyntaxOids);
            context.validate();
            proposed.add(context);
        }

        if (oids.isEmpty() && proposed.isEmpty() && accepted.isEmpty()) {
            throw new IllegalArgumentException("ACSE presentation context list cannot be empty");
        }

        return new PresentationContextParseResult(List.copyOf(oids), List.copyOf(proposed), Set.copyOf(accepted));
    }

    private byte[] encodeUserInformation(int tagNumber, byte[] associationInformation) {
        if (associationInformation == null) {
            associationInformation = new byte[0];
        }

        byte[] oidValue = encodeOidValue(DEFAULT_TRANSFER_SYNTAX_OID);

        byte[] directReference = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 6, 0, oidValue.length, oidValue)
        );

        byte[] indirectReference = BerCodec.encode(
    	    new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { 0x09 })
    	);

        /*
         * Correct EXTERNAL encoding for ACSE user-information:
         *
         *   [30] user-information
         *     EXTERNAL
         *       direct-reference OBJECT IDENTIFIER
         *       indirect-reference INTEGER
         *       data-value-descriptor absent
         *       encoding single-ASN1-type [0]
         *         -> raw association-information APDU bytes
         *
         * Do NOT add:
         *   - [16] / B0
         *   - SET / 31
         *
         * The peer expects the ROS/P3 APDU directly inside [0].
         */
        byte[] singleAsn1Type = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                0,
                0,
                associationInformation.length,
                associationInformation
            )
        );

        byte[] externalValue = concat(
            directReference,
            indirectReference,
            singleAsn1Type
        );

        byte[] external = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                true,
                8,
                0,
                externalValue.length,
                externalValue
            )
        );

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                tagNumber,
                0,
                external.length,
                external
            )
        );
    }

    private byte[] decodeUserInformation(BerTlv wrapped) {
        if (wrapped.tagClass() != TAG_CLASS_CONTEXT || wrapped.tagNumber() != 30) {
            throw new IllegalArgumentException("ACSE expected user-information [30]");
        }

        if (wrapped.value().length == 0) {
            return new byte[0];
        }

        BerTlv external = BerCodec.decodeSingle(wrapped.value());
        if (!external.isUniversal() || external.tagNumber() != 8) {
            throw new IllegalArgumentException("ACSE expected EXTERNAL in user-information");
        }

        return decodeExternalAssociationInformation(external)
            .orElseThrow(() -> new IllegalArgumentException(
                "ACSE user-information does not contain a decodable association-information payload"
            ));
    }

    private Optional<byte[]> decodeExternalAssociationInformation(BerTlv external) {
        List<BerTlv> externalElements = BerCodec.decodeAll(external.value());

        for (BerTlv component : externalElements) {
            /*
             * Correct form:
             *   [0] EXPLICIT ANY
             * where component.value() is already the full embedded APDU encoding
             * (for example 61 xx ... for AARE / ROS result etc.)
             */
            if (component.tagClass() == TAG_CLASS_CONTEXT && component.tagNumber() == 0) {
                if (!component.constructed() || component.value().length == 0) {
                    return Optional.empty();
                }

                return Optional.of(component.value());
            }

            /*
             * Keep these as fallback tolerance only, if you want legacy compatibility.
             */
            if (component.tagClass() == TAG_CLASS_CONTEXT && component.tagNumber() == 1) {
                return Optional.of(component.value());
            }

            if (component.tagClass() == TAG_CLASS_CONTEXT && component.tagNumber() == 2) {
                return Optional.of(component.value());
            }
        }

        return Optional.empty();
    }

    private boolean isWrappedDirectoryString(BerTlv wrapped) {
        BerTlv inner = BerCodec.decodeSingle(wrapped.value());
        return inner.isUniversal()
            && (inner.tagNumber() == 12
                || inner.tagNumber() == 19
                || inner.tagNumber() == 20
                || inner.tagNumber() == 22
                || inner.tagNumber() == 25
                || inner.tagNumber() == 26
                || inner.tagNumber() == 30);
    }

    private String decodeDirectoryString(BerTlv wrapped) {
        BerTlv inner = BerCodec.decodeSingle(wrapped.value());
        return switch (inner.tagNumber()) {
            case 12 -> new String(inner.value(), StandardCharsets.UTF_8);
            case 19, 20, 22, 25, 26 -> new String(inner.value(), StandardCharsets.US_ASCII);
            case 30 -> new String(inner.value(), StandardCharsets.UTF_16BE);
            default -> throw new IllegalArgumentException(
                "ACSE expected directory string inside field [" + wrapped.tagNumber() + "]"
            );
        };
    }

    private byte[] encodeOidValue(String oid) {
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID must contain at least two arcs");
        }

        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);
        if (first < 0 || first > 2 || second < 0 || (first < 2 && second > 39)) {
            throw new IllegalArgumentException("Invalid first OID arcs");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((first * 40) + second);

        for (int i = 2; i < parts.length; i++) {
            long arc = Long.parseLong(parts[i]);
            if (arc < 0) {
                throw new IllegalArgumentException("OID arcs must be >= 0");
            }
            writeBase128(out, arc);
        }

        return out.toByteArray();
    }

    private String decodeOidValue(byte[] oidBytes) {
        if (oidBytes.length == 0) {
            throw new IllegalArgumentException("BER OBJECT IDENTIFIER is empty");
        }

        int first = oidBytes[0] & 0xFF;
        StringBuilder oid = new StringBuilder();
        oid.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = 1; i < oidBytes.length; i++) {
            int octet = oidBytes[i] & 0xFF;
            value = (value << 7) | (octet & 0x7F);
            if ((octet & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }

        if (value != 0) {
            throw new IllegalArgumentException("Invalid BER OBJECT IDENTIFIER encoding");
        }

        return oid.toString();
    }

    private byte[] integerBytes(int value) {
        byte[] out = new byte[4];
        out[0] = (byte) ((value >>> 24) & 0xFF);
        out[1] = (byte) ((value >>> 16) & 0xFF);
        out[2] = (byte) ((value >>> 8) & 0xFF);
        out[3] = (byte) (value & 0xFF);

        int start = 0;
        while (start < 3 && out[start] == 0 && (out[start + 1] & 0x80) == 0) {
            start++;
        }

        byte[] minimal = new byte[4 - start];
        System.arraycopy(out, start, minimal, 0, minimal.length);
        return minimal;
    }

    private void writeBase128(ByteArrayOutputStream out, long arc) {
        int count = 0;
        int[] tmp = new int[10];

        tmp[count++] = (int) (arc & 0x7F);
        arc >>= 7;

        while (arc > 0) {
            tmp[count++] = (int) (arc & 0x7F);
            arc >>= 7;
        }

        for (int i = count - 1; i >= 0; i--) {
            int value = tmp[i];
            if (i != 0) {
                value |= 0x80;
            }
            out.write(value);
        }
    }

    private byte[] concat(byte[]... chunks) {
        int total = 0;
        for (byte[] chunk : chunks) {
            total += chunk.length;
        }

        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }

    private record PresentationContextParseResult(
        List<String> abstractSyntaxOids,
        List<PresentationContext> proposedContexts,
        Set<Integer> acceptedContextIdentifiers
    ) {
        private static PresentationContextParseResult empty() {
            return new PresentationContextParseResult(List.of(), List.of(), Set.of());
        }
    }
}