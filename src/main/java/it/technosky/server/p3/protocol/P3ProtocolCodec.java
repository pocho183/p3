package it.technosky.server.p3.protocol;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.protocol.P3OperationModels.BindRequest;
import it.technosky.server.p3.protocol.P3OperationModels.BindResult;
import it.technosky.server.p3.protocol.P3OperationModels.P3Error;
import it.technosky.server.p3.protocol.P3OperationModels.ReleaseResult;
import it.technosky.server.p3.protocol.P3OperationModels.SubmitRequest;
import it.technosky.server.p3.protocol.P3OperationModels.SubmitResult;
import it.technosky.server.p3.service.P3GatewaySessionService;

@Component
public class P3ProtocolCodec {

    private static final Logger logger = LoggerFactory.getLogger(P3ProtocolCodec.class);

    private final P3BindCodec bindCodec;
    private final P3SubmitCodec submitCodec;
    private final P3ReleaseCodec releaseCodec;
    private final P3GatewaySessionService sessionService;

    public P3ProtocolCodec(
        P3BindCodec bindCodec,
        P3SubmitCodec submitCodec,
        P3ReleaseCodec releaseCodec,
        P3GatewaySessionService sessionService
    ) {
        this.bindCodec = bindCodec;
        this.submitCodec = submitCodec;
        this.releaseCodec = releaseCodec;
        this.sessionService = sessionService;
    }

    public boolean isSupportedApplicationApdu(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length < 4) {
            return false;
        }

        try {
            if (isRoseInvoke(encodedApdu)) {
                return true;
            }

            return bindCodec.isLikelyBindRequest(encodedApdu)
                || submitCodec.isLikelySubmitRequest(encodedApdu)
                || releaseCodec.isLikelyReleaseRequest(encodedApdu);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public byte[] handle(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        try {
            logInboundApdu(encodedApdu);

            if (isRoseInvoke(encodedApdu)) {
                return handleRoseInvoke(session, encodedApdu);
            }

            if (bindCodec.isLikelyBindRequest(encodedApdu)) {
                return handleBind(session, encodedApdu);
            }

            if (submitCodec.isLikelySubmitRequest(encodedApdu)) {
                return handleSubmit(session, encodedApdu);
            }

            if (releaseCodec.isLikelyReleaseRequest(encodedApdu)) {
                return handleRelease(session, encodedApdu);
            }

            logger.warn("Unsupported P3 APDU");
            return bindCodec.encodeBindError(null, new P3Error("unsupported-operation", "Unsupported P3 operation", false));
        } catch (IllegalArgumentException ex) {
            logger.warn("Malformed P3 APDU: {}", ex.getMessage());
            return bindCodec.encodeBindError(null, new P3Error("malformed-apdu", ex.getMessage(), false));
        }
    }
    
    private byte[] handleRoseInvoke(P3GatewaySessionService.SessionState session, byte[] rosInvoke) {
        int opCode = extractRoseOperationCode(rosInvoke, -1);
        byte[] operationArg = extractRoseInvokeArgument(rosInvoke);

        if (operationArg == null || operationArg.length == 0) {
            return wrapRoseErrorIfNeeded(
                rosInvoke,
                submitCodec.encodeSubmitError(
                    new P3Error("malformed-apdu", "Missing ROS argument", false)
                )
            );
        }

        try {
            if (opCode == 3 || submitCodec.isLikelySubmitRequest(operationArg)) {
                SubmitRequest request = submitCodec.decodeSubmitRequest(operationArg);

                String command = "SUBMIT"
                    + " recipient=" + value(request.recipientOrAddress())
                    + ";subject=" + value(request.subject())
                    + ";body=" + value(request.body());

                String response = sessionService.handleCommand(session, command);

                if (response.startsWith("OK")) {
                    String submissionId = parseField(response, "submission-id", "");
                    String messageId = parseField(response, "message-id", "");
                    String senderOrAddress = parseField(response, "sender", "");
                    byte[] nativeResult = submitCodec.encodeSubmitResult(new SubmitResult(submissionId, messageId), senderOrAddress);

                    return wrapRoseResultIfNeeded(rosInvoke, nativeResult);
                }
                
                return wrapRoseErrorIfNeeded(
                    rosInvoke,
                    submitCodec.encodeSubmitError(toError(response))
                );
            }

            if (releaseCodec.isLikelyReleaseRequest(operationArg)) {
                byte[] nativeResult = handleRelease(session, operationArg);
                return wrapRoseResultIfNeeded(rosInvoke, nativeResult);
            }

            return wrapRoseErrorIfNeeded(
                rosInvoke,
                submitCodec.encodeSubmitError(
                    new P3Error(
                        "unsupported-operation",
                        "Unsupported ROS operation code=" + opCode,
                        false
                    )
                )
            );

        } catch (RuntimeException ex) {
            return wrapRoseErrorIfNeeded(
                rosInvoke,
                submitCodec.encodeSubmitError(
                    new P3Error("malformed-apdu", ex.getMessage(), false)
                )
            );
        }
    }
    
    private int extractRoseOperationCode(byte[] rosInvoke, int fallback) {
        try {
            BerTlv root = BerCodec.decodeSingle(rosInvoke);
            int integerCount = 0;

            for (BerTlv child : BerCodec.decodeAll(root.value())) {
                if (child.tagClass() == BerCodec.TAG_CLASS_UNIVERSAL
                    && !child.constructed()
                    && child.tagNumber() == 2) {

                    integerCount++;
                    if (integerCount == 2) {
                        return child.value()[child.value().length - 1] & 0xFF;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return fallback;
    }

    private byte[] extractRoseInvokeArgument(byte[] rosInvoke) {
        try {
            BerTlv root = BerCodec.decodeSingle(rosInvoke);
            int integerCount = 0;

            for (BerTlv child : BerCodec.decodeAll(root.value())) {
                if (child.tagClass() == BerCodec.TAG_CLASS_UNIVERSAL
                    && !child.constructed()
                    && child.tagNumber() == 2) {
                    integerCount++;
                    continue;
                }

                if (integerCount >= 2) {
                    return BerCodec.encode(child);
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private boolean isRoseApdu(byte[] apdu) {
        try {
            BerTlv root = BerCodec.decodeSingle(apdu);
            return root.tagClass() == BerCodec.TAG_CLASS_CONTEXT
                && root.constructed()
                && root.tagNumber() >= 1
                && root.tagNumber() <= 4;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private byte[] handleBind(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        BindRequest request = bindCodec.decodeBindRequest(encodedApdu);

        String command = "BIND"
            + " username=" + value(request.authenticatedIdentity())
            + ";password=" + value(request.password())
            + ";sender=" + value(request.senderOrAddress())
            + ";channel=" + request.requestedChannel().orElse("");

        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            String sender = parseField(response, "sender", request.senderOrAddress());
            String channel = parseField(response, "channel", request.requestedChannel().orElse(""));

            return bindCodec.encodeBindResult(
                request.originalApdu(),
                new BindResult(sender, channel)
            );
        }

        return bindCodec.encodeBindError(
            request.originalApdu(),
            toError(response)
        );
    }

    private byte[] handleSubmit(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        SubmitRequest request = submitCodec.decodeSubmitRequest(encodedApdu);

        String command = "SUBMIT"
            + " recipient=" + value(request.recipientOrAddress())
            + ";subject=" + value(request.subject())
            + ";body=" + value(request.body());

        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            String submissionId = parseField(response, "submission-id", "");
            String messageId = parseField(response, "message-id", "");
            String senderOrAddress = parseField(response, "sender", "");

            byte[] nativeResult = submitCodec.encodeSubmitResult(
                new SubmitResult(submissionId, messageId),
                senderOrAddress
            );

            return wrapRoseResultIfNeeded(encodedApdu, nativeResult);
        }

        byte[] nativeError = submitCodec.encodeSubmitError(toError(response));
        return wrapRoseErrorIfNeeded(encodedApdu, nativeError);
    }
    
    private byte[] wrapRoseResultIfNeeded(byte[] requestApdu, byte[] nativeResult) {
        if (!isRoseInvoke(requestApdu)) {
            return nativeResult;
        }

        int invokeId = extractRoseInvokeId(requestApdu, 1);

        byte[] invokeIdTlv = BerCodec.encode(
            new BerTlv(BerCodec.TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { (byte) invokeId })
        );

        byte[] value = concat(invokeIdTlv, nativeResult);

        return BerCodec.encode(
            new BerTlv(BerCodec.TAG_CLASS_CONTEXT, true, 2, 0, value.length, value)
        );
    }

    private byte[] wrapRoseErrorIfNeeded(byte[] requestApdu, byte[] nativeError) {
        if (!isRoseInvoke(requestApdu)) {
            return nativeError;
        }

        int invokeId = extractRoseInvokeId(requestApdu, 1);

        byte[] invokeIdTlv = BerCodec.encode(
            new BerTlv(BerCodec.TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { (byte) invokeId })
        );

        byte[] errorCode = BerCodec.encode(
            new BerTlv(BerCodec.TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { 1 })
        );

        byte[] parameter = BerCodec.encode(
            new BerTlv(BerCodec.TAG_CLASS_CONTEXT, true, 0, 0, nativeError.length, nativeError)
        );

        byte[] value = concat(invokeIdTlv, errorCode, parameter);

        return BerCodec.encode(
            new BerTlv(BerCodec.TAG_CLASS_CONTEXT, true, 3, 0, value.length, value)
        );
    }

    private boolean isRoseInvoke(byte[] apdu) {
        try {
            BerTlv root = BerCodec.decodeSingle(apdu);
            return root.tagClass() == BerCodec.TAG_CLASS_CONTEXT
                && root.constructed()
                && root.tagNumber() == 1;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private int extractRoseInvokeId(byte[] apdu, int fallback) {
        try {
            BerTlv root = BerCodec.decodeSingle(apdu);
            for (BerTlv child : BerCodec.decodeAll(root.value())) {
                if (child.tagClass() == BerCodec.TAG_CLASS_UNIVERSAL
                    && !child.constructed()
                    && child.tagNumber() == 2
                    && child.value().length > 0) {
                    return child.value()[child.value().length - 1] & 0xFF;
                }
            }
        } catch (RuntimeException ignored) {
        }
        return fallback;
    }

    private byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            if (p != null) len += p.length;
        }

        byte[] out = new byte[len];
        int pos = 0;

        for (byte[] p : parts) {
            if (p != null && p.length > 0) {
                System.arraycopy(p, 0, out, pos, p.length);
                pos += p.length;
            }
        }

        return out;
    }

    private byte[] handleRelease(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        releaseCodec.decodeReleaseRequest(encodedApdu);

        String response = sessionService.handleCommand(session, "UNBIND");
        if (response.startsWith("OK")) {
            return releaseCodec.encodeReleaseResult(new ReleaseResult());
        }

        return releaseCodec.encodeReleaseError(toError(response));
    }

    private P3Error toError(String response) {
        String code = parseField(response, "code", "gateway");
        String detail = parseField(response, "detail", response);
        boolean retryable =
            "interrupted".equals(code)
                || "routing-policy".equals(code)
                || "resource-exhausted".equals(code)
                || "temporarily-unavailable".equals(code)
                || "transient-failure".equals(code)
                || "timeout".equals(code);

        return new P3Error(code, detail, retryable);
    }

    private String parseField(String response, String key, String fallback) {
        if (response == null || response.isBlank()) {
            return fallback;
        }

        String[] tokens = response.split("\\s+");
        for (String token : tokens) {
            int idx = token.indexOf('=');
            if (idx > 0 && idx < token.length() - 1 && key.equals(token.substring(0, idx))) {
                return token.substring(idx + 1);
            }
        }

        return fallback;
    }

    private String value(String maybeNull) {
        return maybeNull == null ? "" : maybeNull;
    }

    private void logInboundApdu(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            logger.info("P3 application decode empty APDU");
            return;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encodedApdu);
            logger.info(
                "P3 application decode tagClass={} constructed={} tagNumber={} len={}",
                tlv.tagClass(),
                tlv.constructed(),
                tlv.tagNumber(),
                tlv.length()
            );
        } catch (RuntimeException ex) {
            logger.info("P3 application decode could not parse BER: {}", ex.getMessage());
        }
    }
}