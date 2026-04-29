package it.technosky.server.p3.x411;

import java.util.Set;

public final class X411TagMap {

    public static final int TAG_CLASS_UNIVERSAL = 0;
    public static final int TAG_CLASS_APPLICATION = 1;
    public static final int TAG_CLASS_CONTEXT = 2;
    public static final int TAG_CLASS_PRIVATE = 3;

    // Context-tag profile used by the current stack for P1 association APDUs.
    // Traceability baseline is documented in docs/icao/X411_MODULE_TRACEABILITY.md.
    public static final int APDU_BIND = 0;
    public static final int APDU_TRANSFER = 1;
    public static final int APDU_RELEASE = 2;
    public static final int APDU_ABORT = 3;
    public static final int APDU_ERROR = 4;
    public static final int APDU_BIND_RESULT = 10;
    public static final int APDU_RELEASE_RESULT = 11;
    public static final int APDU_TRANSFER_RESULT = 12;
    public static final int APDU_NON_DELIVERY_REPORT = 13;
    public static final int APDU_DELIVERY_REPORT = 14;

    public static final int BIND_CALLING_MTA = 0;
    public static final int BIND_CALLED_MTA = 1;
    public static final int BIND_ABSTRACT_SYNTAX = 2;
    public static final int BIND_PROTOCOL_VERSION = 3;
    public static final int BIND_AUTHENTICATION = 4;
    public static final int BIND_SECURITY = 5;
    public static final int BIND_MTS_APDU = 6;
    public static final int BIND_PRESENTATION_CONTEXT = 7;

    public static final int ENVELOPE_MTS_IDENTIFIER = 0;
    public static final int ENVELOPE_PER_RECIPIENT = 1;
    public static final int ENVELOPE_TRACE = 2;
    public static final int ENVELOPE_CONTENT_TYPE = 3;
    public static final int ENVELOPE_ORIGINATOR = 4;
    public static final int ENVELOPE_SECURITY_PARAMETERS = 5;
    public static final int ENVELOPE_EXTENSIONS = 6;

    private static final Set<Integer> ASSOCIATION_APDU_TAGS = Set.of(
        APDU_BIND,
        APDU_TRANSFER,
        APDU_RELEASE,
        APDU_ABORT,
        APDU_ERROR,
        APDU_BIND_RESULT,
        APDU_RELEASE_RESULT,
        APDU_TRANSFER_RESULT,
        APDU_NON_DELIVERY_REPORT,
        APDU_DELIVERY_REPORT
    );


    private static final Set<Integer> BIND_FIELD_TAGS = Set.of(
        BIND_CALLING_MTA,
        BIND_CALLED_MTA,
        BIND_ABSTRACT_SYNTAX,
        BIND_PROTOCOL_VERSION,
        BIND_AUTHENTICATION,
        BIND_SECURITY,
        BIND_MTS_APDU,
        BIND_PRESENTATION_CONTEXT
    );

    private static final Set<Integer> ENVELOPE_BASE_TAGS = Set.of(
        ENVELOPE_MTS_IDENTIFIER,
        ENVELOPE_PER_RECIPIENT,
        ENVELOPE_TRACE,
        ENVELOPE_CONTENT_TYPE,
        ENVELOPE_ORIGINATOR,
        ENVELOPE_SECURITY_PARAMETERS,
        ENVELOPE_EXTENSIONS
    );
    private X411TagMap() {
    }

    public static void validateAssociationApdu(BerApduTag apduTag) {
        if (apduTag.tagClass() != TAG_CLASS_CONTEXT) {
            throw new IllegalArgumentException(
                "Unsupported X.411 association APDU tag class [" + apduTag.tagClass() + "]"
            );
        }
        validateAssociationApduTag(apduTag.tagNumber());
    }

    public static void validateAssociationApduTag(int tagNumber) {
        if (!ASSOCIATION_APDU_TAGS.contains(tagNumber)) {
            throw new IllegalArgumentException("Unsupported X.411 association APDU tag [" + tagNumber + "]");
        }
    }

    public static void validateContextTagClass(int tagClass, String fieldName) {
        if (tagClass != TAG_CLASS_CONTEXT) {
            throw new IllegalArgumentException(
                "Expected context-specific tag class for " + fieldName + " but found [" + tagClass + "]"
            );
        }
    }

    public static boolean isKnownBindFieldTag(int tagNumber) {
        return BIND_FIELD_TAGS.contains(tagNumber);
    }

    public static boolean isKnownEnvelopeFieldTag(int tagNumber) {
        return ENVELOPE_BASE_TAGS.contains(tagNumber);
    }

    public static boolean isExtensionEnvelopeFieldTag(int tagNumber) {
        return tagNumber > ENVELOPE_EXTENSIONS;
    }

    public static Set<Integer> associationApduTags() {
        return ASSOCIATION_APDU_TAGS;
    }

    public record BerApduTag(int tagClass, int tagNumber) {
    }

}
