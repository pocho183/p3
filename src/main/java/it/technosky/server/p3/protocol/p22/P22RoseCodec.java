package it.technosky.server.p3.protocol.p22;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.stereotype.Component;

import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.protocol.p22.P22OperationModels.P22Error;
import it.technosky.server.p3.protocol.p22.P22OperationModels.RoseInvoke;

@Component
public class P22RoseCodec {

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    // ROSE APDU tags
    private static final int ROSE_INVOKE_TAG = 1;
    private static final int ROSE_RETURN_RESULT_TAG = 2;
    private static final int ROSE_RETURN_ERROR_TAG = 3;

    public boolean isLikelyRoseInvoke(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);
            return tlv.tagClass() == TAG_CLASS_APPLICATION
                && tlv.constructed()
                && tlv.tagNumber() == ROSE_INVOKE_TAG;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public RoseInvoke decodeInvoke(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("Empty ROSE APDU");
        }

        BerTlv root = BerCodec.decodeSingle(encoded);
        if (root.tagClass() != TAG_CLASS_APPLICATION
            || !root.constructed()
            || root.tagNumber() != ROSE_INVOKE_TAG) {
            throw new IllegalArgumentException("Not a ROSE invoke APDU");
        }

        List<BerTlv> fields = BerCodec.decodeAll(root.value());
        if (fields.size() < 3) {
            throw new IllegalArgumentException("ROSE invoke must contain invokeId, operationCode and argument");
        }

        BerTlv invokeIdField = fields.get(0);
        BerTlv operationCodeField = fields.get(1);

        int invokeId = decodeIntegerField(invokeIdField);
        int operationCode = decodeIntegerField(operationCodeField);

        BerTlv argumentField = fields.get(2);
        byte[] argument = BerCodec.encode(argumentField);

        return new RoseInvoke(invokeId, operationCode, argument);
    }

    public byte[] encodeReturnResult(int invokeId, byte[] resultPayload) {
        byte[] invokeIdField = encodeIntegerUniversal(invokeId);

        byte[] resultField = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                0,
                0,
                resultPayload.length,
                resultPayload
            )
        );

        byte[] seqValue = concat(invokeIdField, resultField);

        byte[] seq = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                true,
                16,
                0,
                seqValue.length,
                seqValue
            )
        );

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                ROSE_RETURN_RESULT_TAG,
                0,
                seq.length,
                seq
            )
        );
    }

    public byte[] encodeReturnError(P22Error error) {
        byte[] invokeIdField = encodeIntegerUniversal(error.invokeId());
        byte[] codeField = encodeUtf8ContextField(0, error.code());
        byte[] detailField = encodeUtf8ContextField(1, error.detail());
        byte[] retryableField = encodeUtf8ContextField(2, Boolean.toString(error.retryable()));

        byte[] errorPayload = concat(codeField, detailField, retryableField);

        byte[] wrappedError = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                0,
                0,
                errorPayload.length,
                errorPayload
            )
        );

        byte[] seqValue = concat(invokeIdField, wrappedError);

        byte[] seq = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                true,
                16,
                0,
                seqValue.length,
                seqValue
            )
        );

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                ROSE_RETURN_ERROR_TAG,
                0,
                seq.length,
                seq
            )
        );
    }

    private int decodeIntegerField(BerTlv tlv) {
        if (tlv.tagClass() != TAG_CLASS_UNIVERSAL || tlv.constructed() || tlv.tagNumber() != 2) {
            throw new IllegalArgumentException("Expected universal INTEGER");
        }

        byte[] value = tlv.value();
        if (value == null || value.length == 0 || value.length > 4) {
            throw new IllegalArgumentException("Unsupported INTEGER length");
        }

        int out = 0;
        for (byte b : value) {
            out = (out << 8) | (b & 0xFF);
        }
        return out;
    }

    private byte[] encodeIntegerUniversal(int value) {
        if (value == 0) {
            return BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { 0x00 })
            );
        }

        byte[] raw = new byte[4];
        raw[0] = (byte) ((value >>> 24) & 0xFF);
        raw[1] = (byte) ((value >>> 16) & 0xFF);
        raw[2] = (byte) ((value >>> 8) & 0xFF);
        raw[3] = (byte) (value & 0xFF);

        int start = 0;
        while (start < 3 && raw[start] == 0 && (raw[start + 1] & 0x80) == 0) {
            start++;
        }

        byte[] minimal = new byte[4 - start];
        System.arraycopy(raw, start, minimal, 0, minimal.length);

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, minimal.length, minimal)
        );
    }

    private byte[] encodeUtf8ContextField(int tagNumber, String value) {
        byte[] bytes = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);

        byte[] utf8 = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 12, 0, bytes.length, bytes)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, utf8.length, utf8)
        );
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            if (a != null) {
                total += a.length;
            }
        }

        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            if (a != null && a.length > 0) {
                System.arraycopy(a, 0, out, offset, a.length);
                offset += a.length;
            }
        }
        return out;
    }
}