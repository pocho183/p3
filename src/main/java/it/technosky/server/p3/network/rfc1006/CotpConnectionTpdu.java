package it.technosky.server.p3.network.rfc1006;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public record CotpConnectionTpdu(
    byte type,
    int destinationReference,
    int sourceReference,
    int tpduClass,
    Optional<Integer> tpduSize,
    List<Parameter> unknownParameters
) {
    public static final byte PDU_CR = (byte) 0xE0;
    public static final byte PDU_CC = (byte) 0xD0;

    public static final byte PARAM_TPDU_SIZE = (byte) 0xC0;

    public record Parameter(byte code, byte[] value) {
    }

    public static CotpConnectionTpdu parse(byte[] tpdu) {
        if (tpdu.length < 7) {
            throw new IllegalArgumentException("COTP CR/CC TPDU too short");
        }
        int li = tpdu[0] & 0xFF;
        if (li + 1 > tpdu.length || li < 6) {
            throw new IllegalArgumentException("Invalid COTP length indicator");
        }
        byte type = (byte) (tpdu[1] & (byte) 0xF0);
        if (type != PDU_CR && type != PDU_CC) {
            throw new IllegalArgumentException("Expected COTP CR/CC TPDU");
        }
        int dstRef = ((tpdu[2] & 0xFF) << 8) | (tpdu[3] & 0xFF);
        int srcRef = ((tpdu[4] & 0xFF) << 8) | (tpdu[5] & 0xFF);
        int clazz = tpdu[6] & 0x0F;

        Optional<Integer> tpduSize = Optional.empty();
        List<Parameter> unknown = new ArrayList<>();

        int offset = 7;
        while (offset + 2 <= li + 1) {
            byte code = tpdu[offset++];
            int paramLen = tpdu[offset++] & 0xFF;
            if (offset + paramLen > li + 1) {
                throw new IllegalArgumentException("Invalid COTP parameter length");
            }
            byte[] value = Arrays.copyOfRange(tpdu, offset, offset + paramLen);
            if (code == PARAM_TPDU_SIZE && paramLen == 1) {
                tpduSize = Optional.of(1 << (value[0] & 0xFF));
            } else {
                unknown.add(new Parameter(code, value));
            }
            offset += paramLen;
        }
        return new CotpConnectionTpdu(type, dstRef, srcRef, clazz, tpduSize, unknown);
    }

    public byte[] serialize() {
        List<byte[]> params = new ArrayList<>();
        tpduSize.ifPresent(size -> {
            int exponent = 0;
            int cursor = size;
            while (cursor > 1) {
                cursor >>= 1;
                exponent++;
            }
            params.add(new byte[] {PARAM_TPDU_SIZE, 0x01, (byte) exponent});
        });
        for (Parameter parameter : unknownParameters) {
            byte[] out = new byte[2 + parameter.value.length];
            out[0] = parameter.code;
            out[1] = (byte) parameter.value.length;
            System.arraycopy(parameter.value, 0, out, 2, parameter.value.length);
            params.add(out);
        }

        int len = 7;
        for (byte[] p : params) {
            len += p.length;
        }
        byte[] tpdu = new byte[len];
        tpdu[0] = (byte) (len - 1);
        tpdu[1] = type;
        tpdu[2] = (byte) ((destinationReference >> 8) & 0xFF);
        tpdu[3] = (byte) (destinationReference & 0xFF);
        tpdu[4] = (byte) ((sourceReference >> 8) & 0xFF);
        tpdu[5] = (byte) (sourceReference & 0xFF);
        tpdu[6] = (byte) (tpduClass & 0x0F);
        int offset = 7;
        for (byte[] p : params) {
            System.arraycopy(p, 0, tpdu, offset, p.length);
            offset += p.length;
        }
        return tpdu;
    }

    public int negotiatedMaxUserData() {
        return tpduSize.orElse(16_384);
    }
}
