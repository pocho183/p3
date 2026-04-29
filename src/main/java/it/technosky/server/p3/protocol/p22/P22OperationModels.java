package it.technosky.server.p3.protocol.p22;

import java.util.Optional;

public final class P22OperationModels {

    private P22OperationModels() {
    }

    public record RoseInvoke(
        int invokeId,
        int operationCode,
        byte[] argument
    ) {
    }

    public record InterPersonalMessageRequest(
        int invokeId,
        Optional<String> originator,
        Optional<String> recipient,
        Optional<String> headingIdentifier,
        Optional<String> subject,
        Optional<String> body,
        byte[] originalArgument
    ) {
    }

    public record InterPersonalMessageResult(
        int invokeId,
        String deliveryMessage
    ) {
    }

    public record P22Error(
        int invokeId,
        String code,
        String detail,
        boolean retryable
    ) {
    }
}