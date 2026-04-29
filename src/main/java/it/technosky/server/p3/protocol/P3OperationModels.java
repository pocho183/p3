package it.technosky.server.p3.protocol;

import java.util.Optional;

public final class P3OperationModels {

    private P3OperationModels() {
    }

    public sealed interface P3Request permits BindRequest, SubmitRequest, ReleaseRequest {
    }

    public sealed interface P3Response permits BindResult, SubmitResult, ReleaseResult, P3Error {
    }

    public record BindRequest(
        String authenticatedIdentity,
        String password,
        String senderOrAddress,
        Optional<String> requestedChannel,
        byte[] originalApdu
    ) implements P3Request {
    }

    public record BindResult(
        String senderOrAddress,
        String effectiveChannel
    ) implements P3Response {
    }

    public record SubmitRequest(
        String recipientOrAddress,
        String subject,
        String body,
        byte[] originalApdu
    ) implements P3Request {
    }

    public record SubmitResult(
        String submissionId,
        String internalMessageId
    ) implements P3Response {
    }

    public record ReleaseRequest(
        byte[] originalApdu
    ) implements P3Request {
    }

    public record ReleaseResult() implements P3Response {
    }

    public record P3Error(
        String code,
        String detail,
        boolean retryable
    ) implements P3Response {
    }
}
