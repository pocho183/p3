package it.technosky.server.p3.network;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import it.technosky.server.p3.acse.AcseAssociationProtocol;
import it.technosky.server.p3.acse.AcseModels;
import it.technosky.server.p3.asn1.BerCodec;
import it.technosky.server.p3.asn1.BerTlv;
import it.technosky.server.p3.protocol.P3GatewaySessionService;
import it.technosky.server.p3.protocol.P3ProtocolCodec;
import it.technosky.server.p3.protocol.p22.P22ProtocolCodec;
import it.technosky.server.p3.protocol.rfc1006.CotpConnectionTpdu;


@Component
@ConditionalOnProperty(prefix = "amhs.p3.gateway", name = "enabled", havingValue = "true")
public class P3GatewayServer {

    private static final Logger logger = LoggerFactory.getLogger(P3GatewayServer.class);

    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final int MAX_TPKT_LENGTH = 65_535;

    private static final byte COTP_PDU_CR = (byte) 0xE0;
    private static final byte COTP_PDU_CC = (byte) 0xD0;
    private static final byte COTP_PDU_DT = (byte) 0xF0;
    private static final byte COTP_PDU_DR = (byte) 0x80;
    private static final byte COTP_PDU_DC = (byte) 0xC0;

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int GATEWAY_APDU_MIN_TAG = 0;
    private static final int GATEWAY_APDU_MAX_TAG = 12;

    private static final int PRESENTATION_MODE_SELECTOR_TAG = 0;
    private static final int PRESENTATION_NORMAL_MODE_PARAMETERS_TAG = 2;
    private static final int PRESENTATION_CP_CONTEXT_DEFINITION_LIST_TAG = 4;
    private static final int PRESENTATION_CPA_CONTEXT_DEFINITION_RESULT_LIST_TAG = 5;

    private static final String DEFAULT_PRESENTATION_TRANSFER_SYNTAX_OID = "2.1.1";

    private final String host;
    private final int port;
    private final boolean tlsEnabled;
    private final boolean needClientAuth;
    private final boolean textWelcomeEnabled;
    private final ListenerProfile listenerProfile;
    private final SSLContext tls;
    private final P3GatewaySessionService sessionService;
    private final P3ProtocolCodec p3ProtocolCodec;
    private final P22ProtocolCodec p22ProtocolCodec;
    private final AcseAssociationProtocol acseAssociationProtocol;
    private final ExecutorService clientExecutor;
    private final AtomicLong connectionSequence = new AtomicLong(0);

    public P3GatewayServer(
        @Value("${amhs.p3.gateway.host:0.0.0.0}") String host,
        @Value("${amhs.p3.gateway.port:102}") int port,
        @Value("${amhs.p3.gateway.max-sessions:64}") int maxSessions,
        @Value("${amhs.p3.gateway.tls.enabled:false}") boolean tlsEnabled,
        @Value("${amhs.p3.gateway.tls.need-client-auth:false}") boolean needClientAuth,
        @Value("${amhs.p3.gateway.text.welcome-enabled:false}") boolean textWelcomeEnabled,
        @Value("${amhs.p3.gateway.listener-profile:STANDARD_P3}") String listenerProfile,
        SSLContext tls,
        P3GatewaySessionService sessionService,
        P3ProtocolCodec p3ProtocolCodec,
        P22ProtocolCodec p22ProtocolCodec,
        AcseAssociationProtocol acseAssociationProtocol
    ) {
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("amhs.p3.gateway.port out of range: " + port);
        }
        if (maxSessions < 1) {
            throw new IllegalArgumentException("amhs.p3.gateway.max-sessions must be >= 1");
        }

        this.host = host;
        this.port = port;
        this.tlsEnabled = tlsEnabled;
        this.needClientAuth = needClientAuth;
        this.textWelcomeEnabled = textWelcomeEnabled;
        this.listenerProfile = ListenerProfile.from(listenerProfile);
        this.tls = tls;
        this.sessionService = sessionService;
        this.p3ProtocolCodec = p3ProtocolCodec;
        this.p22ProtocolCodec = p22ProtocolCodec;
        this.acseAssociationProtocol = acseAssociationProtocol;
        this.clientExecutor = Executors.newFixedThreadPool(maxSessions, new NamedDaemonThreadFactory());

        logger.info(
            "AMHS P3 gateway listener-profile={} supported={}",
            this.listenerProfile,
            this.listenerProfile.supportedProtocolsSummary()
        );
    }

    public void start() throws Exception {
        if (tlsEnabled) {
            SSLServerSocket server = (SSLServerSocket) tls.getServerSocketFactory()
                .createServerSocket(port, 50, InetAddress.getByName(host));
            server.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
            server.setNeedClientAuth(needClientAuth);
            logger.info("AMHS P3 gateway TLS server listening on {}:{}", host, port);
            acceptLoop(server);
            return;
        }

        ServerSocket server = new ServerSocket(port, 50, InetAddress.getByName(host));
        logger.info("AMHS P3 gateway clear transport server listening on {}:{}", host, port);
        acceptLoop(server);
    }

    private void acceptLoop(ServerSocket server) throws Exception {
        while (true) {
            Socket socket = server.accept();
            long connectionId = connectionSequence.incrementAndGet();
            logger.info(
                "P3 gateway connection #{} from {}:{} to local-port={}",
                connectionId,
                socket.getInetAddress(),
                socket.getPort(),
                socket.getLocalPort()
            );
            clientExecutor.execute(() -> handleClient(connectionId, socket));
        }
    }

    private void handleClient(long connectionId, Socket socket) {
        try (
            socket;
            PushbackInputStream input = new PushbackInputStream(socket.getInputStream(), 16);
            OutputStream output = socket.getOutputStream()
        ) {
        	socket.setTcpNoDelay(false);
            P3GatewaySessionService.SessionState session = sessionService.newSession();

            byte[] preview = input.readNBytes(8);
            if (preview.length == 0) {
                return;
            }
            input.unread(preview);

            ProtocolKind protocolKind = detectProtocol(preview);
            logger.info(
                "P3 gateway connection #{} protocol-detect kind={} first-octets={}",
                connectionId,
                protocolKind,
                toHex(preview)
            );

            if (!listenerProfile.supports(protocolKind)) {
                logger.warn(
                    "P3 gateway connection #{} rejected protocol={} for listener-profile={} supported={}",
                    connectionId,
                    protocolKind,
                    listenerProfile,
                    listenerProfile.supportedProtocolsSummary()
                );
                return;
            }

            switch (protocolKind) {
                case TEXT_COMMAND -> handleTextSession(connectionId, session, input, output);
                case BER_APDU -> handleBerSession(connectionId, session, input, output);
                case RFC1006_TPKT -> handleRfc1006Session(connectionId, session, input, output);
                default -> logger.warn("P3 gateway connection #{} unsupported protocol={}", connectionId, protocolKind);
            }

        } catch (Exception ex) {
            if (ex instanceof EOFException || ex instanceof SocketException) {
                logger.debug("P3 gateway connection #{} ended: {}", connectionId, ex.getMessage());
            } else {
                logger.warn("P3 gateway connection #{} error: {}", connectionId, ex.getMessage(), ex);
            }
        }
    }

    private void handleTextSession(
        long connectionId,
        P3GatewaySessionService.SessionState session,
        PushbackInputStream input,
        OutputStream output
    ) throws Exception {
        try (
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
            PrintWriter writer = new PrintWriter(
                new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8)),
                true
            )
        ) {
            if (textWelcomeEnabled) {
                writer.println("OK code=gateway-ready");
            }

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }

                String response = sessionService.handleCommand(session, line);
                writer.println(response);

                if (session.isClosed()) {
                    logger.info(
                        "P3 gateway connection #{} text session closed by command {}",
                        connectionId,
                        commandName(line)
                    );
                    return;
                }
            }
        }
    }

    private void handleBerSession(
        long connectionId,
        P3GatewaySessionService.SessionState session,
        PushbackInputStream input,
        OutputStream output
    ) throws Exception {
        int pduIndex = 0;

        while (true) {
            byte[] pdu = readBerPdu(input);
            if (pdu == null) {
                logger.info("P3 gateway connection #{} BER session closed after {} APDU(s)", connectionId, pduIndex);
                return;
            }

            pduIndex++;

            logger.info(
                "P3 gateway connection #{} BER APDU #{} len={} first-bytes={}",
                connectionId,
                pduIndex,
                pdu.length,
                toHexPreview(pdu, 128)
            );

            byte[] response = p3ProtocolCodec.handle(session, pdu);
            output.write(response);
            output.flush();

            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} BER session closed by release", connectionId);
                return;
            }
        }
    }

    private byte[] readBerPdu(PushbackInputStream inputStream) throws Exception {
        int firstOctet = inputStream.read();
        if (firstOctet < 0) {
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(firstOctet);

        int secondOctet = inputStream.read();
        if (secondOctet < 0) {
            throw new EOFException("Missing BER length octet");
        }
        out.write(secondOctet);

        int valueLength;
        if ((secondOctet & 0x80) == 0) {
            valueLength = secondOctet;
        } else {
            int numLenOctets = secondOctet & 0x7F;
            if (numLenOctets == 0) {
                throw new IllegalArgumentException("Indefinite BER length is not supported");
            }

            byte[] lenBytes = inputStream.readNBytes(numLenOctets);
            if (lenBytes.length != numLenOctets) {
                throw new EOFException("Truncated BER length");
            }
            out.writeBytes(lenBytes);

            valueLength = 0;
            for (byte b : lenBytes) {
                valueLength = (valueLength << 8) | (b & 0xFF);
            }
        }

        byte[] value = inputStream.readNBytes(valueLength);
        if (value.length != valueLength) {
            throw new EOFException("Truncated BER value");
        }

        out.writeBytes(value);
        return out.toByteArray();
    }

    private void handleRfc1006Session(
    	    long connectionId,
    	    P3GatewaySessionService.SessionState session,
    	    PushbackInputStream input,
    	    OutputStream output
    	) throws Exception {
	    ByteArrayOutputStream segmentedPayload = new ByteArrayOutputStream();
	    int pduIndex = 0;

	    while (true) {
	        CotpFrame frame = readRfc1006Frame(input);
	        if (frame == null) {
	            logger.info(
	                "P3 gateway connection #{} RFC1006 session closed after {} payload(s)",
	                connectionId,
	                pduIndex
	            );
	            return;
	        }

	        if (frame.type == COTP_PDU_CR) {
	            CotpConnectionTpdu request = CotpConnectionTpdu.parse(frame.payload);
	            CotpConnectionTpdu confirm = new CotpConnectionTpdu(
	                CotpConnectionTpdu.PDU_CC,
	                request.sourceReference(),
	                request.destinationReference(),
	                request.tpduClass(),
	                request.tpduSize(),
	                request.unknownParameters()
	            );
	            sendTpktFrame(output, confirm.serialize());
	            output.flush();
	            logger.info("P3 gateway connection #{} RFC1006 COTP connection confirmed", connectionId);
	            continue;
	        }

	        if (frame.type == COTP_PDU_DR) {
	            sendTpktFrame(output, new byte[] { 0x06, COTP_PDU_DC, 0x00, 0x00, 0x00, 0x00, 0x00 });
	            output.flush();
	            logger.info("P3 gateway connection #{} RFC1006 disconnect requested by peer", connectionId);
	            return;
	        }

	        if (frame.type != COTP_PDU_DT) {
	            logger.warn(
	                "P3 gateway connection #{} ignoring unsupported TPDU type=0x{}",
	                connectionId,
	                toHexByte(frame.type)
	            );
	            continue;
	        }

	        segmentedPayload.writeBytes(frame.userData);
	        if (!frame.endOfTsdu) {
	            continue;
	        }

	        byte[] payload = segmentedPayload.toByteArray();
	        segmentedPayload.reset();

	        if (payload.length == 0) {
	            continue;
	        }

	        pduIndex++;
	        String kind = classifyPayload(payload);

	        logger.info(
	            "P3 gateway connection #{} RFC1006 payload #{} len={} kind={} first-bytes={}",
	            connectionId,
	            pduIndex,
	            payload.length,
	            kind,
	            toHexPreview(payload, 192)
	        );

	        if (isSessionAbortWithUserData(payload)) {
	            logger.warn(
	                "P3 gateway connection #{} peer sent Session/PRES ABORT payload={}",
	                connectionId,
	                toHexPreview(payload, 128)
	            );
	            return;
	        }

	        byte[] applicationPdu = extractApplicationPdu(payload, kind);
	        
	        if (applicationPdu == null) {
	            if (isSessionAbortSpdu(payload)) {
	                logger.info(
	                    "P3 gateway connection #{} peer closed session payload={}",
	                    connectionId,
	                    toHexPreview(payload, 64)
	                );
	                return;
	            }

	            logger.warn(
	                "P3 gateway connection #{} payload #{} unsupported kind={} first-bytes={}",
	                connectionId,
	                pduIndex,
	                kind,
	                toHexPreview(payload, 192)
	            );

	            sendRfc1006Disconnect(output);
	            return;
	        }

	        if (isTinyPostBindReleaseOrAckApdu(applicationPdu) || isWrappedTinyReleaseOrAckApdu(applicationPdu)) {
        	    logger.info(
        	        "Peer sent ACSE release/ack; closing gracefully first-bytes={}",
        	        toHexPreview(applicationPdu, 64)
        	    );
        	    return;
        	}
	        
	        if (isPeerRosReject(applicationPdu)) {
	            logger.info("Peer sent ROS reject/control; ignoring");
	            continue;
	        }
	        
	        logger.info(
	            "P3 gateway delivering application PDU to ASN.1 handler len={} first-bytes={}",
	            applicationPdu.length,
	            toHexPreview(applicationPdu, 128)
	        );

	        if (applicationPdu.length <= 16) {
	            logger.info(
	                "P3 gateway application PDU is short len={} first-bytes={}",
	                applicationPdu.length,
	                toHexPreview(applicationPdu, 64)
	            );
	        }

	        logger.info("P3 BER dispatch detail {}", describeTopLevelBer(applicationPdu));

	        boolean p3Supported = p3ProtocolCodec.isSupportedApplicationApdu(applicationPdu);
	        boolean p22Supported = p22ProtocolCodec.isSupportedApplicationApdu(applicationPdu);
	        boolean smallControl = isSmallPostBindControlApdu(applicationPdu);
	        boolean tinyReleaseOrAck = isTinyPostBindReleaseOrAckApdu(applicationPdu) || isWrappedTinyReleaseOrAckApdu(applicationPdu);
	        boolean peerRejectControl = isPeerPostBindRejectControlApdu(applicationPdu);
	        boolean benignZeroEnum = isBenignZeroEnumeratedControl(applicationPdu);

	        logger.info(
	        	    "dispatch probe p3Supported={} p22Supported={} smallControl={} tinyReleaseOrAck={} peerRejectControl={} benignZeroEnum={}",
	        	    p3Supported,
	        	    p22Supported,
	        	    smallControl,
	        	    tinyReleaseOrAck,
	        	    peerRejectControl,
	        	    benignZeroEnum
	        	);

	        byte[] applicationResponse;

	        if (benignZeroEnum) {
	            continue;
	        } else if (isPeerRejectOrAbortControl(applicationPdu)) {
	            continue;
	        } else if (peerRejectControl) {
	            continue;
	        } else if (smallControl) {
	            logger.info(
	                "Peer sent small post-bind control/reject; ignoring first-bytes={}",
	                toHexPreview(applicationPdu, 64)
	            );
	            continue;
	        } else if (p22Supported) {
	            applicationResponse = p22ProtocolCodec.handle(applicationPdu);
	        } else if (p3Supported) {
	            applicationResponse = p3ProtocolCodec.handle(session, applicationPdu);
	        } else {
	            sendRfc1006Disconnect(output);
	            return;
	        }

	        byte[] wrappedResponse = rewrapResponse(payload, kind, applicationResponse);

	        logger.info(
	            "P3 outbound application response len={} first-bytes={}",
	            applicationResponse.length,
	            toHexPreview(applicationResponse, 128)
	        );
	        logger.info(
	            "P3 outbound wrapped response len={} first-bytes={}",
	            wrappedResponse.length,
	            toHexPreview(wrappedResponse, 192)
	        );

	        sendRfc1006Dt(output, wrappedResponse);

	        if (session.isClosed()) {
	            logger.info("P3 gateway connection #{} RFC1006 session closed by release", connectionId);
	            return;
	        }
	    }
	}
    
    private boolean isWrappedTinyReleaseOrAckApdu(byte[] apdu) {
        if (apdu == null || apdu.length != 14) {
            return false;
        }

        // 61 0C 30 0A 02 01 01 A0 05 62 03 80 01 00
        return (apdu[0] & 0xFF) == 0x61
            && (apdu[1] & 0xFF) == 0x0C
            && (apdu[2] & 0xFF) == 0x30
            && (apdu[3] & 0xFF) == 0x0A
            && (apdu[7] & 0xFF) == 0xA0
            && (apdu[8] & 0xFF) == 0x05
            && (apdu[9] & 0xFF) == 0x62
            && (apdu[10] & 0xFF) == 0x03
            && (apdu[11] & 0xFF) == 0x80
            && (apdu[12] & 0xFF) == 0x01
            && (apdu[13] & 0xFF) == 0x00;
    }
    
    private boolean isPeerRejectOrAbortControl(byte[] apdu) {
        if (apdu == null || apdu.length < 5 || apdu.length > 32) {
            return false;
        }

        // presentation carrier containing ROS reject:
        // 61 0E 30 0C 02 01 03 A0 07 A4 05 05 00 80 01 00
        if ((apdu[0] & 0xFF) == 0x61 && containsByte(apdu, (byte) 0xA4)) {
            return true;
        }

        // direct ROS reject:
        // A4 05 05 00 80 01 00
        return (apdu[0] & 0xFF) == 0xA4;
    }

    private boolean containsByte(byte[] data, byte value) {
        for (byte b : data) {
            if (b == value) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isPeerRosReject(byte[] apdu) {
        if (apdu == null || apdu.length < 4 || apdu.length > 32) {
            return false;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(apdu);

            // ROS reject: [4]
            return root.tagClass() == TAG_CLASS_CONTEXT
                && root.constructed()
                && root.tagNumber() == 4;
        } catch (RuntimeException ex) {
            return false;
        }
    }
    
    private boolean isBenignZeroEnumeratedControl(byte[] apdu) {
        return apdu != null
            && apdu.length == 2
            && (apdu[0] & 0xFF) == 0x0A
            && (apdu[1] & 0xFF) == 0x00;
    }

    private boolean isPeerPostBindRejectControlApdu(byte[] apdu) {
        if (apdu == null || apdu.length < 8 || apdu.length > 32) {
            return false;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(apdu);

            // observed peer control:
            // 61 0C 30 0A 02 01 01 A0 05 62 03 80 01 00
            if (root.tagClass() != TAG_CLASS_APPLICATION || !root.constructed() || root.tagNumber() != 1) {
                return false;
            }

            List<BerTlv> fields = BerCodec.decodeAll(root.value());
            fields = unwrapSequenceIfPresent(fields);

            if (fields.size() < 2) {
                return false;
            }

            BerTlv invokeId = fields.get(0);
            BerTlv opField = fields.get(1);

            if (invokeId.tagClass() != TAG_CLASS_UNIVERSAL
                || invokeId.constructed()
                || invokeId.tagNumber() != 2) {
                return false;
            }

            if (opField.tagClass() != TAG_CLASS_CONTEXT || !opField.constructed()) {
                return false;
            }

            List<BerTlv> opChildren = decodeChildrenLenient(opField);
            if (opChildren.size() != 1) {
                return false;
            }

            BerTlv inner = opChildren.get(0);

            // peer reject/control often arrives as embedded application[2]
            return inner.tagClass() == TAG_CLASS_APPLICATION
                && inner.constructed()
                && inner.tagNumber() == 2;
        } catch (RuntimeException ex) {
            return false;
        }
    }
    
    private boolean isTinyPostBindReleaseOrAckApdu(byte[] apdu) {
        if (apdu == null || apdu.length < 3 || apdu.length > 32) {
            return false;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(apdu);

            // direct ACSE release/ack: 62 03 80 01 00
            if (root.tagClass() == TAG_CLASS_APPLICATION
                && root.constructed()
                && root.tagNumber() == 2
                && root.value() != null
                && root.value().length == 3) {
                return true;
            }

            // wrapped presentation carrier:
            // 61 0C 30 0A 02 01 01 A0 05 62 03 80 01 00
            if (root.tagClass() == TAG_CLASS_APPLICATION
                && root.constructed()
                && root.tagNumber() == 1) {

                List<BerTlv> children = BerCodec.decodeAll(root.value());
                children = unwrapSequenceIfPresent(children);

                for (BerTlv child : children) {
                    if (containsTinyReleaseAck(child)) {
                        return true;
                    }
                }
            }

            return false;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean containsTinyReleaseAck(BerTlv node) {
        if (node == null) {
            return false;
        }

        try {
            byte[] encoded = BerCodec.encode(node);

            if (encoded.length == 5
                && (encoded[0] & 0xFF) == 0x62
                && (encoded[1] & 0xFF) == 0x03
                && (encoded[2] & 0xFF) == 0x80
                && (encoded[3] & 0xFF) == 0x01
                && (encoded[4] & 0xFF) == 0x00) {
                return true;
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    if (containsTinyReleaseAck(child)) {
                        return true;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return false;
    }
    
    private boolean isSmallPostBindControlApdu(byte[] apdu) {
        if (apdu == null || apdu.length < 12 || apdu.length > 24) {
            return false;
        }

        // Exact observed NULL/status control:
        // 61 0E 30 0C 02 01 xx A0 07 A4 05 05 00 80 01 00
        if ((apdu[0] & 0xFF) == 0x61
            && apdu.length == 16
            && (apdu[2] & 0xFF) == 0x30
            && (apdu[4] & 0xFF) == 0x02
            && (apdu[5] & 0xFF) == 0x01
            && (apdu[7] & 0xFF) == 0xA0
            && (apdu[9] & 0xFF) == 0xA4
            && (apdu[10] & 0xFF) == 0x05
            && (apdu[11] & 0xFF) == 0x05
            && (apdu[12] & 0xFF) == 0x00
            && (apdu[13] & 0xFF) == 0x80
            && (apdu[14] & 0xFF) == 0x01
            && (apdu[15] & 0xFF) == 0x00) {
            return true;
        }

        // Exact observed APPLICATION 2 control:
        // 61 0C 30 0A 02 01 xx A0 05 62 03 80 01 00
        if ((apdu[0] & 0xFF) == 0x61
            && apdu.length == 14
            && (apdu[2] & 0xFF) == 0x30
            && (apdu[4] & 0xFF) == 0x02
            && (apdu[5] & 0xFF) == 0x01
            && (apdu[7] & 0xFF) == 0xA0
            && (apdu[9] & 0xFF) == 0x62
            && (apdu[10] & 0xFF) == 0x03
            && (apdu[11] & 0xFF) == 0x80
            && (apdu[12] & 0xFF) == 0x01
            && (apdu[13] & 0xFF) == 0x00) {
            return true;
        }

        return false;
    }

    private List<BerTlv> unwrapSequenceIfPresent(List<BerTlv> fields) {
        if (fields.size() == 1) {
            BerTlv only = fields.get(0);
            if (only.tagClass() == BerCodec.TAG_CLASS_UNIVERSAL &&
                only.constructed() &&
                only.tagNumber() == 16) {
                List<BerTlv> seqChildren = decodeChildrenLenient(only);
                if (!seqChildren.isEmpty()) {
                    return seqChildren;
                }
            }
        }
        return fields;
    }

    private List<BerTlv> decodeChildrenLenient(BerTlv tlv) {
        if (tlv == null || tlv.value() == null || tlv.value().length == 0) {
            return Collections.emptyList();
        }
        try {
            return BerCodec.decodeAll(tlv.value());
        } catch (Exception ex) {
            logger.debug("failed to decode BER children tagClass={} tagNumber={} len={}",
                tlv.tagClass(), tlv.tagNumber(), tlv.length(), ex);
            return Collections.emptyList();
        }
    }

    private String describeTopLevelBer(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return "empty";
        }
        try {
            BerTlv tlv = BerCodec.decodeSingle(payload);
            return "tagClass=" + tlv.tagClass()
                + " constructed=" + tlv.constructed()
                + " tagNumber=" + tlv.tagNumber()
                + " len=" + tlv.length();
        } catch (RuntimeException ex) {
            return "decode-failed:" + ex.getMessage();
        }
    }

    private CotpFrame readRfc1006Frame(PushbackInputStream input) throws Exception {
        int version = input.read();
        if (version < 0) {
            return null;
        }

        int reserved = input.read();
        int lenHi = input.read();
        int lenLo = input.read();
        if (reserved < 0 || lenHi < 0 || lenLo < 0) {
            throw new EOFException("Connection closed while reading TPKT header");
        }

        if (version != TPKT_VERSION || reserved != TPKT_RESERVED) {
            throw new IllegalArgumentException("Invalid TPKT header");
        }

        int tpktLength = ((lenHi & 0xFF) << 8) | (lenLo & 0xFF);
        if (tpktLength < 7 || tpktLength > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("Invalid TPKT frame length: " + tpktLength);
        }

        byte[] cotpTpdu = input.readNBytes(tpktLength - 4);
        if (cotpTpdu.length != tpktLength - 4) {
            throw new EOFException("Truncated TPKT payload");
        }

        int lengthIndicator = cotpTpdu[0] & 0xFF;
        if (lengthIndicator + 1 > cotpTpdu.length || lengthIndicator < 1) {
            throw new IllegalArgumentException("Invalid COTP length indicator: " + lengthIndicator);
        }

        byte type = (byte) (cotpTpdu[1] & 0xF0);

        if (type == COTP_PDU_CR || type == COTP_PDU_CC || type == COTP_PDU_DR || type == COTP_PDU_DC) {
            return new CotpFrame(type, true, new byte[0], cotpTpdu);
        }

        if (type != COTP_PDU_DT) {
            return new CotpFrame(type, true, new byte[0], cotpTpdu);
        }

        if (lengthIndicator < 2) {
            throw new IllegalArgumentException("Unsupported COTP DT header");
        }

        boolean eot = (cotpTpdu[2] & 0x80) != 0;
        int dataOffset = lengthIndicator + 1;
        byte[] userData = Arrays.copyOfRange(cotpTpdu, dataOffset, cotpTpdu.length);

        return new CotpFrame(type, eot, userData, cotpTpdu);
    }

    private void sendRfc1006Dt(OutputStream output, byte[] payload) throws Exception {
        byte[] response = payload == null ? new byte[0] : payload;

        byte[] tpdu = new byte[3 + response.length];
        tpdu[0] = 0x02;
        tpdu[1] = COTP_PDU_DT;
        tpdu[2] = (byte) 0x80;
        if (response.length > 0) {
            System.arraycopy(response, 0, tpdu, 3, response.length);
        }

        sendTpktFrame(output, tpdu);
        output.flush();
    }

    // Send to the channel
    private void sendTpktFrame(OutputStream output, byte[] tpdu) throws Exception {
        int length = 4 + tpdu.length;
        if (length > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("TPKT frame too large: " + length);
        }

        byte[] frame = new byte[length];

        frame[0] = TPKT_VERSION;
        frame[1] = TPKT_RESERVED;
        frame[2] = (byte) ((length >> 8) & 0xFF);
        frame[3] = (byte) (length & 0xFF);

        System.arraycopy(tpdu, 0, frame, 4, tpdu.length);

        output.write(frame);
    }

    private void sendRfc1006Disconnect(OutputStream output) throws Exception {
        sendTpktFrame(output, new byte[] { 0x06, COTP_PDU_DR, 0x00, 0x00, 0x00, 0x00, 0x00 });
        output.flush();
    }

    private ProtocolKind detectProtocol(byte[] preview) {
        int first = preview[0] & 0xFF;

        if (looksLikeRfc1006(preview)) {
            return ProtocolKind.RFC1006_TPKT;
        }
        if (looksLikeTlsClientHello(preview)) {
            return ProtocolKind.TLS_CLIENT_HELLO;
        }
        if (looksLikeBer(preview)) {
            return ProtocolKind.BER_APDU;
        }
        if (first >= 0x20 && first <= 0x7E) {
            return ProtocolKind.TEXT_COMMAND;
        }
        return ProtocolKind.UNKNOWN_BINARY;
    }

    private boolean looksLikeRfc1006(byte[] preview) {
        return preview.length >= 4
            && (preview[0] & 0xFF) == 0x03
            && (preview[1] & 0xFF) == 0x00
            && (((preview[2] & 0xFF) << 8) | (preview[3] & 0xFF)) >= 4;
    }

    private boolean looksLikeTlsClientHello(byte[] preview) {
        return preview.length >= 3
            && (preview[0] & 0xFF) == 0x16
            && (preview[1] & 0xFF) == 0x03
            && ((preview[2] & 0xFF) >= 0x01 && (preview[2] & 0xFF) <= 0x04);
    }

    private boolean looksLikeBer(byte[] preview) {
        if (preview == null || preview.length < 2) {
            return false;
        }

        int first = preview[0] & 0xFF;
        if (first == 0x00 || first == 0xFF) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(preview);
            int totalLength = tlv.headerLength() + tlv.length();
            return totalLength > 0 && totalLength <= preview.length;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private String classifyPayload(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return "EMPTY";
        }

        int first = payload[0] & 0xFF;

        if (first == 0x0D || first == 0x01 || first == 0x0E || first == 0x19) {
            return "OSI_SESSION_SPDU";
        }

        if (first == 0x09 && looksLikeShortSessionParameterCarrier(payload)) {
            return "OSI_SESSION_SPDU";
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(payload);

            if (looksLikeTopLevelAcse(payload)) {
                return "ACSE_APDU";
            }

            // Presentation PPDU root: SET
            if (tlv.tagClass() == TAG_CLASS_UNIVERSAL
                && tlv.constructed()
                && tlv.tagNumber() == 17) {
                return "OSI_PRESENTATION_PPDU";
            }

            // fully-encoded-data [APPLICATION 1] only if it really matches PDV structure
            if (looksLikePresentationFullyEncodedData(tlv)) {
                return "OSI_PRESENTATION_USER_DATA";
            }

            // Native application APDUs only after wrapper checks
            if (p3ProtocolCodec.isSupportedApplicationApdu(payload)) {
                return "BER_APDU";
            }

            if (p22ProtocolCodec.isSupportedApplicationApdu(payload)) {
                return "BER_APDU";
            }

            // PDV-list directly
            if (tlv.tagClass() == TAG_CLASS_UNIVERSAL
                && tlv.constructed()
                && tlv.tagNumber() == 16) {
                List<BerTlv> fields = BerCodec.decodeAll(tlv.value());
                boolean hasContextId = false;
                boolean hasPresentationDataValues = false;

                for (BerTlv field : fields) {
                    if (field.tagClass() == TAG_CLASS_UNIVERSAL
                        && !field.constructed()
                        && field.tagNumber() == 2) {
                        hasContextId = true;
                    }

                    if (field.tagClass() == TAG_CLASS_CONTEXT
                        && field.constructed()
                        && (field.tagNumber() == 0 || field.tagNumber() == 1 || field.tagNumber() == 2)) {
                        hasPresentationDataValues = true;
                    }
                }

                if (hasContextId && hasPresentationDataValues) {
                    return "OSI_PRESENTATION_USER_DATA";
                }
            }

            if (looksLikeBer(payload)) {
                return "BER_APDU";
            }
        } catch (RuntimeException ignored) {
        }

        return "UNKNOWN_BINARY";
    }

    private boolean isSessionAbortSpdu(byte[] payload) {
        if (payload == null || payload.length < 2) {
            return false;
        }

        int si = payload[0] & 0xFF;
        if (si != 0x19) {
            return false;
        }

        int li = payload[1] & 0xFF;
        if (li == 0xFF) {
            return payload.length >= 4;
        }

        return payload.length >= 2 + li;
    }

    private boolean isSessionAbortWithUserData(byte[] payload) {
        return payload != null && payload.length >= 2 && (payload[0] & 0xFF) == 0x19;
    }

    private byte[] extractApplicationPdu(byte[] payload, String kind) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        
        switch (kind) {
            case "BER_APDU":
                return payload;

            case "OSI_SESSION_SPDU": {
                byte[] sessionUserData = extractSessionUserData(payload);
                if (sessionUserData == null || sessionUserData.length == 0) {
                    return null;
                }

                String nestedKind = classifyPayload(sessionUserData);
                logger.info(
                    "P3 gateway session user-data classified kind={} first-bytes={}",
                    nestedKind,
                    toHexPreview(sessionUserData, 192)
                );

                // If carrier removal already produced a real app APDU, stop here.
                if (p3ProtocolCodec.isSupportedApplicationApdu(sessionUserData)
                    || p22ProtocolCodec.isSupportedApplicationApdu(sessionUserData)) {
                    return sessionUserData;
                }

                return extractApplicationPdu(sessionUserData, nestedKind);
            }

            case "OSI_PRESENTATION_PPDU": {
                byte[] ppduUserData = unwrapPresentation(payload);
                if (ppduUserData == null || ppduUserData.length == 0) {
                    return null;
                }

                String nestedKind = classifyPayload(ppduUserData);
                logger.info(
                    "P3 gateway presentation user-data classified kind={} first-bytes={}",
                    nestedKind,
                    toHexPreview(ppduUserData, 192)
                );

                if (p3ProtocolCodec.isSupportedApplicationApdu(ppduUserData)
                    || p22ProtocolCodec.isSupportedApplicationApdu(ppduUserData)) {
                    return ppduUserData;
                }

                return extractApplicationPdu(ppduUserData, nestedKind);
            }

            case "ACSE_APDU": {
                byte[] acseUserData = unwrapAcse(payload);
                if (acseUserData == null || acseUserData.length == 0) {
                    return payload;
                }

                String nestedKind = classifyPayload(acseUserData);
                logger.info(
                    "P3 gateway ACSE user-data classified kind={} first-bytes={}",
                    nestedKind,
                    toHexPreview(acseUserData, 192)
                );

                // If ACSE unwrap already produced the application APDU, stop here.
                if (p3ProtocolCodec.isSupportedApplicationApdu(acseUserData)
                    || p22ProtocolCodec.isSupportedApplicationApdu(acseUserData)) {
                    return acseUserData;
                }

                if (!Arrays.equals(acseUserData, payload)) {
                    return extractApplicationPdu(acseUserData, nestedKind);
                }

                return acseUserData;
            }

            case "OSI_PRESENTATION_USER_DATA": {
                byte[] unwrapped = unwrapPresentationUserData(payload);
                if (unwrapped == null || unwrapped.length == 0) {
                    return null;
                }

                logger.info(
                    "P3 gateway unwrapped presentation user-data len={} first-bytes={}",
                    unwrapped.length,
                    toHexPreview(unwrapped, 192)
                );
                
                if (isTinyPostBindReleaseOrAckApdu(unwrapped) || isWrappedTinyReleaseOrAckApdu(payload)) {
                    return payload;
                }

                if (p3ProtocolCodec.isSupportedApplicationApdu(unwrapped)
                    || p22ProtocolCodec.isSupportedApplicationApdu(unwrapped)) {
                    return unwrapped;
                }
                
                if (isRosInvokeOrResultOrError(unwrapped)) {
                    logger.info(
                        "P3 gateway using full ROS APDU len={} first-bytes={}",
                        unwrapped.length,
                        toHexPreview(unwrapped, 192)
                    );
                    return unwrapped;
                }
                
                if (isFullRosApdu(unwrapped)) {
                    return unwrapped;
                }

                byte[] deeper = unwrapToRealApplicationApdu(unwrapped);
                if (deeper != null
                    && (p3ProtocolCodec.isSupportedApplicationApdu(deeper)
                        || p22ProtocolCodec.isSupportedApplicationApdu(deeper))) {
                    logger.info(
                        "P3 gateway deeper-unwrapped supported application payload len={} first-bytes={}",
                        deeper.length,
                        toHexPreview(deeper, 192)
                    );
                    return deeper;
                }

                String nestedKind = classifyPayload(unwrapped);
                if (!"BER_APDU".equals(nestedKind)) {
                    byte[] nested = extractApplicationPdu(unwrapped, nestedKind);
                    if (nested != null) {
                        return nested;
                    }
                }
                
                /*
                 * Important:
                 * small release/control-like presentation payloads may not unwrap into a
                 * dispatchable native APDU, but the original presentation carrier can still
                 * be handled by the P22 compat/control path.
                 */
                logger.info(
                    "P3 gateway presentation unwrap did not yield a native APDU; falling back to original presentation carrier first-bytes={}",
                    toHexPreview(payload, 192)
                );
                return payload;
            }

            default:
                return null;
        }
    }
    
    private boolean isRosInvokeOrResultOrError(byte[] apdu) {
        if (apdu == null || apdu.length < 4) {
            return false;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(apdu);

            return root.tagClass() == TAG_CLASS_CONTEXT
                && root.constructed()
                && (
                    root.tagNumber() == 1 || // invoke
                    root.tagNumber() == 2 || // returnResult
                    root.tagNumber() == 3    // returnError
                );
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private byte[] unwrapPresentationUserData(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return null;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);

            // fully-encoded-data [APPLICATION 1]
            if (tlv.tagClass() == TAG_CLASS_APPLICATION
                && tlv.constructed()
                && tlv.tagNumber() == 1) {

                List<BerTlv> pdvLists = BerCodec.decodeAll(tlv.value());
                for (BerTlv pdvList : pdvLists) {
                    byte[] payload = unwrapPresentationPdvList(pdvList);
                    if (payload != null && payload.length > 0) {
                        return payload;
                    }
                }
                return null;
            }

            // PDV-list directly
            if (tlv.tagClass() == TAG_CLASS_UNIVERSAL
                && tlv.constructed()
                && tlv.tagNumber() == 16) {
                return unwrapPresentationPdvList(tlv);
            }

            // presentation-data-values directly
            if (tlv.tagClass() == TAG_CLASS_CONTEXT
                && tlv.constructed()
                && (tlv.tagNumber() == 0 || tlv.tagNumber() == 1 || tlv.tagNumber() == 2)) {
                return unwrapPresentationDataValues(tlv);
            }

            return null;
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap presentation user-data: {}", ex.getMessage());
            return null;
        }
    }
    
    private byte[] unwrapPresentationPdvList(BerTlv pdvList) {
        if (pdvList == null
            || pdvList.tagClass() != TAG_CLASS_UNIVERSAL
            || !pdvList.constructed()
            || pdvList.tagNumber() != 16) {
            return null;
        }

        try {
            List<BerTlv> fields = BerCodec.decodeAll(pdvList.value());

            for (BerTlv field : fields) {
                boolean isPresentationDataValues =
                    field.tagClass() == TAG_CLASS_CONTEXT
                        && field.constructed()
                        && (field.tagNumber() == 0 || field.tagNumber() == 1 || field.tagNumber() == 2);

                if (isPresentationDataValues) {
                    return unwrapPresentationDataValues(field);
                }
            }

            return null;
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap PDV-list: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] unwrapPresentationDataValues(BerTlv field) {
        if (field == null
            || field.tagClass() != TAG_CLASS_CONTEXT
            || !field.constructed()
            || (field.tagNumber() != 0 && field.tagNumber() != 1 && field.tagNumber() != 2)) {
            return null;
        }

        try {
            byte[] inner = field.value();
            if (inner == null || inner.length == 0) {
                return null;
            }

            BerTlv carried = BerCodec.decodeSingle(inner);
            return BerCodec.encode(carried);

        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap presentation-data-values: {}", ex.getMessage());
            return null;
        }
    }
    
    private byte[] unwrapToRealApplicationApdu(byte[] encoded) {
        if (encoded == null || encoded.length < 16) {
            return null;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(encoded);
            return findBestNestedApplicationApdu(root);
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap nested presentation value: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] findBestNestedApplicationApdu(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            byte[] encoded = BerCodec.encode(node);

            // Accept only true top-level carriers here.
            if (looksLikeTopLevelAcse(encoded)) {
                return encoded;
            }

            if (p22ProtocolCodec.isSupportedApplicationApdu(encoded)) {
                return encoded;
            }

            // IMPORTANT:
            // Do NOT accept arbitrary context-specific P3 fragments here.
            // A nested A2/A0 may be only an OR-address or submit subfield.
            if (isFullRosApdu(encoded)) {
                return encoded;
            }

            if (node.tagClass() == TAG_CLASS_UNIVERSAL
                && !node.constructed()
                && node.tagNumber() == 4
                && node.value() != null
                && node.value().length >= 2) {

                try {
                    BerTlv inner = BerCodec.decodeSingle(node.value());
                    return findBestNestedApplicationApdu(inner);
                } catch (RuntimeException ignored) {
                    return null;
                }
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    byte[] found = findBestNestedApplicationApdu(child);
                    if (found != null) {
                        return found;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private boolean isFullRosApdu(byte[] apdu) {
        if (apdu == null || apdu.length < 8) {
            return false;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(apdu);

            // Your trace shows full ROS invoke starts with A1:
            // A1 ... 02 01 invokeId 02 01 operationCode ...
            if (root.tagClass() != TAG_CLASS_CONTEXT || !root.constructed()) {
                return false;
            }

            int tag = root.tagNumber();
            if (tag != 1 && tag != 2 && tag != 3 && tag != 4) {
                return false;
            }

            List<BerTlv> fields = BerCodec.decodeAll(root.value());

            boolean hasInvokeId = false;
            for (BerTlv field : fields) {
                if (field.tagClass() == TAG_CLASS_UNIVERSAL
                    && !field.constructed()
                    && field.tagNumber() == 2) {
                    hasInvokeId = true;
                    break;
                }
            }

            return hasInvokeId;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private byte[] buildPresentationUserData(byte[] applicationApdu, int presentationContextId) {
        if (applicationApdu == null || applicationApdu.length == 0) {
            return null;
        }

        byte[] contextIdBytes = integerBytes(presentationContextId);

        byte[] contextIdField = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                false,
                2,
                0,
                contextIdBytes.length,
                contextIdBytes
            )
        );

        byte[] presentationDataValues = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                0,
                0,
                applicationApdu.length,
                applicationApdu
            )
        );

        byte[] pdvValue = concat(List.of(contextIdField, presentationDataValues));

        byte[] pdvList = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                true,
                16,
                0,
                pdvValue.length,
                pdvValue
            )
        );

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                1,
                0,
                pdvList.length,
                pdvList
            )
        );
    }

    private byte[] rewrapResponse(byte[] inboundPayload, String inboundKind, byte[] applicationResponse) {
        if (applicationResponse == null) {
            return new byte[0];
        }

        logger.info("rewrap inboundKind={}", inboundKind);
        logger.info("rewrap inboundPayload={}", toHexPreview(inboundPayload, 192));
        logger.info("rewrap applicationResponse={}", toHexPreview(applicationResponse, 192));

        if ("BER_APDU".equals(inboundKind)) {
            return applicationResponse;
        }

        if ("ACSE_APDU".equals(inboundKind)) {
            byte[] acseResponse = wrapAcseEnvelope(applicationResponse, inboundPayload);
            return acseResponse != null ? acseResponse : applicationResponse;
        }

        if ("OSI_PRESENTATION_PPDU".equals(inboundKind)) {
            return rewrapPresentationPpdu(inboundPayload, applicationResponse);
        }

        if ("OSI_PRESENTATION_USER_DATA".equals(inboundKind)) {
            return rewrapPresentationUserData(inboundPayload, applicationResponse);
        }

        if ("OSI_SESSION_SPDU".equals(inboundKind)) {
            return rewrapSessionSpdu(inboundPayload, applicationResponse);
        }

        return applicationResponse;
    }

    private byte[] rewrapPresentationPpdu(byte[] inboundPresentation, byte[] applicationResponse) {
        byte[] inboundAcse = extractPresentationAcseApdu(inboundPresentation);
        byte[] acseResponse = wrapAcseEnvelope(applicationResponse, inboundAcse);
        byte[] payloadForPresentation = acseResponse != null ? acseResponse : applicationResponse;

        logger.info(
            "P3 presentation branch using raw ACSE-for-presentation={}",
            toHexPreview(payloadForPresentation, 192)
        );

        byte[] rebuiltPresentation = buildPresentationConnectAccept(inboundPresentation, payloadForPresentation);
        if (rebuiltPresentation != null) {
            logger.info(
                "P3 outbound rebuilt presentation len={} first-bytes={}",
                rebuiltPresentation.length,
                toHexPreview(rebuiltPresentation, 192)
            );
            return rebuiltPresentation;
        }

        return payloadForPresentation;
    }

    private byte[] rewrapPresentationUserData(byte[] inboundPresentationUserData, byte[] applicationResponse) {
        int contextId = extractPresentationContextId(inboundPresentationUserData);
        byte[] rebuiltUserData = buildPresentationUserData(applicationResponse, contextId);

        logger.info(
            "P3 presentation-user-data branch contextId={} rebuilt-first-bytes={}",
            contextId,
            rebuiltUserData == null ? "<null>" : toHexPreview(rebuiltUserData, 192)
        );

        return rebuiltUserData != null ? rebuiltUserData : applicationResponse;
    }

    private byte[] rewrapSessionSpdu(byte[] inboundSessionSpdu, byte[] applicationResponse) {
        byte[] sessionUserData = extractSessionUserData(inboundSessionSpdu);
        if (sessionUserData == null || sessionUserData.length == 0) {
            return applicationResponse;
        }

        String nestedKind = classifyPayload(sessionUserData);

        byte[] nestedResponse;
        if ("OSI_PRESENTATION_USER_DATA".equals(nestedKind)) {
            nestedResponse = rewrapPresentationUserData(sessionUserData, applicationResponse);
        } else {
            nestedResponse = rewrapNestedInsideSession(sessionUserData, nestedKind, applicationResponse);
        }

        if (looksLikePostBindSessionCarrier(inboundSessionSpdu)) {
            return rebuildPostBindSessionCarrier(inboundSessionSpdu, nestedResponse);
        }

        byte[] rebuiltSession = replaceSessionUserData(inboundSessionSpdu, nestedResponse);
        return rebuiltSession != null ? rebuiltSession : nestedResponse;
    }
    
    private byte[] replaceSessionUserData(byte[] spdu, byte[] newValue) {
        if (spdu == null || spdu.length == 0 || newValue == null) {
            return null;
        }

        /*
         * Preserve the exact post-bind outer carrier:
         *   01 00 01 03 19 01 03 <payload>
         */
        if (looksLikePostBindSessionCarrier(spdu)) {
            byte[] rebuilt = rebuildPostBindSessionCarrier(spdu, newValue);
            if (rebuilt != null) {
                logger.info(
                    "P3 session rebuilt via post-bind carrier preserve len={} first-bytes={}",
                    rebuilt.length,
                    toHexPreview(rebuilt, 192)
                );
                return rebuilt;
            }
        }

        /*
         * Preserve short session parameter carriers like:
         *   09 <LI> ... C1 <len> <payload>
         */
        if (looksLikeShortSessionParameterCarrier(spdu)) {
            byte[] rebuilt = rebuildShortSessionParameterCarrier(spdu, newValue);
            if (rebuilt != null) {
                logger.info(
                    "P3 session rebuilt via short session carrier preserve len={} first-bytes={}",
                    rebuilt.length,
                    toHexPreview(rebuilt, 192)
                );
                return rebuilt;
            }
        }

        byte[] rebuiltByParameters = replaceSessionUserDataByParameters(spdu, newValue);
        if (rebuiltByParameters != null) {
            return rebuiltByParameters;
        }

        int payloadOffset = locateEmbeddedAsn1Offset(spdu);
        if (payloadOffset < 0) {
            logger.warn("Could not locate embedded ASN.1 payload in session SPDU");
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(Arrays.copyOfRange(spdu, 0, payloadOffset));
        out.writeBytes(newValue);

        byte[] rebuilt = out.toByteArray();

        logger.info(
            "P3 session rebuilt by prefix-preserve len={} first-bytes={}",
            rebuilt.length,
            toHexPreview(rebuilt, 192)
        );

        return rebuilt;
    }

    private byte[] rewrapNestedInsideSession(byte[] sessionUserData, String nestedKind, byte[] applicationResponse) {
        if ("OSI_PRESENTATION_PPDU".equals(nestedKind)) {
            return rewrapPresentationPpdu(sessionUserData, applicationResponse);
        }

        if ("OSI_PRESENTATION_USER_DATA".equals(nestedKind)) {
            int contextId = extractPresentationContextId(sessionUserData);
            return buildPresentationUserData(applicationResponse, contextId);
        }
        
        if ("ACSE_APDU".equals(nestedKind)) {
            byte[] acseResponse = wrapAcseEnvelope(applicationResponse, sessionUserData);
            if (acseResponse != null) {
                logger.info(
                    "P3 session->acse branch rebuilt-first-bytes={}",
                    toHexPreview(acseResponse, 192)
                );
                return acseResponse;
            }
            return applicationResponse;
        }

        if ("BER_APDU".equals(nestedKind)) {
            byte[] maybePresentationWrapped = tryBuildPostBindPresentationUserData(sessionUserData, applicationResponse);
            if (maybePresentationWrapped != null) {
                logger.info(
                    "P3 session->postbind-presentation branch rebuilt-first-bytes={}",
                    toHexPreview(maybePresentationWrapped, 192)
                );
                return maybePresentationWrapped;
            }
        }

        return applicationResponse;
    }

    private byte[] tryBuildPostBindPresentationUserData(byte[] inboundSessionUserData, byte[] applicationResponse) {
        if (inboundSessionUserData == null || inboundSessionUserData.length == 0 || applicationResponse == null) {
            return null;
        }

        try {
            /*
             * If inboundSessionUserData is really an ACSE APDU containing presentation user-data,
             * preserve that structure first.
             */
            if (looksLikeTopLevelAcse(inboundSessionUserData)) {
                byte[] acseUserData = unwrapAcse(inboundSessionUserData);

                if (acseUserData != null && acseUserData.length > 0) {
                    String acseNestedKind = classifyPayload(acseUserData);

                    if ("OSI_PRESENTATION_USER_DATA".equals(acseNestedKind)) {
                        int contextId = extractPresentationContextId(acseUserData);
                        byte[] rebuiltPresUd = buildPresentationUserData(applicationResponse, contextId);

                        if (rebuiltPresUd != null) {
                            byte[] rebuiltAcse = wrapAcseEnvelope(rebuiltPresUd, inboundSessionUserData);
                            if (rebuiltAcse != null) {
                                return rebuiltAcse;
                            }
                        }
                    }
                }

                byte[] rebuiltAcse = wrapAcseEnvelope(applicationResponse, inboundSessionUserData);
                if (rebuiltAcse != null) {
                    return rebuiltAcse;
                }
            }

            /*
             * If the fallback extraction landed on a BER blob that itself is presentation user-data,
             * rebuild that directly.
             */
            String kind = classifyPayload(inboundSessionUserData);
            if ("OSI_PRESENTATION_USER_DATA".equals(kind)) {
                int contextId = extractPresentationContextId(inboundSessionUserData);
                byte[] rebuiltPresUd = buildPresentationUserData(applicationResponse, contextId);
                if (rebuiltPresUd != null) {
                    return rebuiltPresUd;
                }
            }

            /*
             * Last safe synthesis:
             * build fully-encoded-data with a conservative context id.
             */
            byte[] synthesized = buildPresentationUserData(applicationResponse, 1);
            if (synthesized != null) {
                return synthesized;
            }
        } catch (RuntimeException ex) {
            logger.warn("Failed to build post-bind presentation user-data: {}", ex.getMessage(), ex);
        }

        return null;
    }

    private int extractPresentationContextId(byte[] encoded) { 
    	if (encoded == null || encoded.length == 0) { 
    		return 1; 
    	} try { 
    		BerTlv root = BerCodec.decodeSingle(encoded); 
    		if (!looksLikePresentationFullyEncodedData(root)) {
    			return 1; 
    		} 
    		List<BerTlv> pdvItems = BerCodec.decodeAll(root.value()); 
    		for (BerTlv pdvItem : pdvItems) { 
    			if (pdvItem.tagClass() != TAG_CLASS_UNIVERSAL || !pdvItem.constructed() || pdvItem.tagNumber() != 16) { 
    				continue; 
    			} 
    			List<BerTlv> fields = BerCodec.decodeAll(pdvItem.value()); 
    			for (BerTlv field : fields) { 
    				if (field.tagClass() == TAG_CLASS_UNIVERSAL && !field.constructed() && field.tagNumber() == 2) { 
    					return decodeSmallPositiveInteger(field.value()); 
    				} 
    			} 
    		} 
    	} catch (RuntimeException ignored) {
    		
    	}
    	return 1; 
    }
    
    private byte[] extractPresentationAcseApdu(byte[] presentationPpdu) {
        if (presentationPpdu == null || presentationPpdu.length == 0) {
            return null;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(presentationPpdu);
            if (root.tagClass() != TAG_CLASS_UNIVERSAL || !root.constructed() || root.tagNumber() != 17) {
                return null;
            }
            return findAcseApduInNode(root);
        } catch (RuntimeException ex) {
            logger.debug("Failed to extract ACSE APDU from Presentation PPDU: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] findAcseApduInNode(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            byte[] encoded = BerCodec.encode(node);

            if (looksLikeTopLevelAcse(encoded)) {
                return encoded;
            }

            if (!node.constructed()) {
                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                byte[] found = findAcseApduInNode(child);
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private byte[] buildPresentationUserDataFromAcse(byte[] acseApdu, int presentationContextId) {
        if (acseApdu == null || acseApdu.length == 0) {
            return null;
        }

        byte[] contextIdBytes = integerBytes(presentationContextId);

        byte[] contextIdField = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, contextIdBytes.length, contextIdBytes)
        );

        byte[] presentationDataValues = BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, 0, 0, acseApdu.length, acseApdu)
        );

        byte[] pdvListValue = concat(List.of(contextIdField, presentationDataValues));

        byte[] pdvList = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, pdvListValue.length, pdvListValue)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_APPLICATION, true, 1, 0, pdvList.length, pdvList)
        );
    }

    private byte[] buildPresentationConnectAccept(byte[] inboundPresentation, byte[] applicationResponse) {
        try {
            logger.info("presentation CPA rebuild inbound={}", toHexPreview(inboundPresentation, 192));
            logger.info("presentation CPA rebuild app-response={}", toHexPreview(applicationResponse, 192));

            BerTlv root = BerCodec.decodeSingle(inboundPresentation);
            if (root.tagClass() != TAG_CLASS_UNIVERSAL || !root.constructed() || root.tagNumber() != 17) {
                logger.warn("presentation CPA rebuild: inbound root is not expected Presentation SET");
                return null;
            }

            List<BerTlv> rootChildren = BerCodec.decodeAll(root.value());

            BerTlv modeSelector = null;
            BerTlv inboundNormalModeParameters = null;

            for (BerTlv child : rootChildren) {
                if (child.tagClass() == TAG_CLASS_CONTEXT && child.constructed() && child.tagNumber() == PRESENTATION_MODE_SELECTOR_TAG) {
                    modeSelector = child;
                } else if (child.tagClass() == TAG_CLASS_CONTEXT && child.constructed() && child.tagNumber() == PRESENTATION_NORMAL_MODE_PARAMETERS_TAG) {
                    inboundNormalModeParameters = child;
                }
            }

            List<byte[]> rebuiltRootChildren = new ArrayList<>();

            if (modeSelector != null) {
                rebuiltRootChildren.add(BerCodec.encode(modeSelector));
            }

            byte[] rebuiltNormalModeParameters = buildPresentationNormalModeParameters(
                inboundNormalModeParameters,
                applicationResponse
            );
            if (rebuiltNormalModeParameters == null) {
                return null;
            }
            rebuiltRootChildren.add(rebuiltNormalModeParameters);

            logger.info("presentation CPA root-children count={}", rebuiltRootChildren.size());

            byte[] newRootValue = concat(rebuiltRootChildren);

            byte[] rebuilt = BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, true, 17, 0, newRootValue.length, newRootValue)
            );

            logger.info("presentation CPA rebuilt={}", toHexPreview(rebuilt, 192));
            return rebuilt;
        } catch (RuntimeException ex) {
            logger.warn("Failed to build Presentation CPA: {}", ex.getMessage(), ex);
            return null;
        }
    }

    private byte[] buildPresentationNormalModeParameters(
        BerTlv inboundNormalModeParameters,
        byte[] applicationResponse
    ) {
        List<byte[]> children = new ArrayList<>();
        BerTlv inboundPayloadChild = null;
        BerTlv inboundContextDefinitionList = null;

        if (inboundNormalModeParameters != null) {
            try {
                for (BerTlv child : BerCodec.decodeAll(inboundNormalModeParameters.value())) {
                    if (isPresentationCpContextDefinitionList(child)) {
                        inboundContextDefinitionList = child;
                    } else if (inboundPayloadChild == null) {
                        inboundPayloadChild = child;
                    }
                }
            } catch (RuntimeException ex) {
                logger.debug("Could not inspect inbound normal-mode-parameters: {}", ex.getMessage());
            }
        }

        byte[] resultList = buildPresentationContextDefinitionResultList(inboundContextDefinitionList);
        if (resultList != null) {
            children.add(resultList);
        }

        byte[] rebuiltPayloadChild = buildPresentationPayloadChildFromInbound(inboundPayloadChild, applicationResponse);
        if (rebuiltPayloadChild == null) {
            logger.warn("Could not rebuild presentation payload child");
            return null;
        }

        children.add(rebuiltPayloadChild);

        logger.info(
            "presentation normal-mode-parameters rebuilt with {} child(ren) payload-first-bytes={}",
            children.size(),
            toHexPreview(applicationResponse, 128)
        );

        byte[] value = concat(children);

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, PRESENTATION_NORMAL_MODE_PARAMETERS_TAG, 0, value.length, value)
        );
    }

    private boolean isPresentationCpContextDefinitionList(BerTlv tlv) {
        return tlv != null
            && tlv.tagClass() == TAG_CLASS_CONTEXT
            && tlv.constructed()
            && tlv.tagNumber() == PRESENTATION_CP_CONTEXT_DEFINITION_LIST_TAG;
    }

    private byte[] buildPresentationContextDefinitionResultList(BerTlv inboundListChild) {
        try {
            List<PresentationContextDefinition> inboundDefinitions = parsePresentationContextDefinitions(inboundListChild);

            logger.info("presentation inbound context-definition count={}", inboundDefinitions.size());
            for (PresentationContextDefinition def : inboundDefinitions) {
                logger.info(
                    "presentation inbound context-definition id={} abstract-syntax={}",
                    def.presentationContextId(),
                    def.abstractSyntaxOid()
                );
            }

            List<byte[]> encodedItems = new ArrayList<>();

            if (!inboundDefinitions.isEmpty()) {
                for (PresentationContextDefinition ignored : inboundDefinitions) {
                    encodedItems.add(encodePresentationContextResultItem(0, DEFAULT_PRESENTATION_TRANSFER_SYNTAX_OID));
                }
            } else {
                for (int i = 0; i < 4; i++) {
                    encodedItems.add(encodePresentationContextResultItem(0, DEFAULT_PRESENTATION_TRANSFER_SYNTAX_OID));
                }
            }

            byte[] seqValue = concat(encodedItems);

            return BerCodec.encode(
                new BerTlv(
                    TAG_CLASS_CONTEXT,
                    true,
                    PRESENTATION_CPA_CONTEXT_DEFINITION_RESULT_LIST_TAG,
                    0,
                    seqValue.length,
                    seqValue
                )
            );
        } catch (RuntimeException ex) {
            logger.warn("Failed to build presentation-context-definition-result-list: {}", ex.getMessage(), ex);
            return null;
        }
    }

    private byte[] encodePresentationContextResultItem(int result, String transferSyntaxOid) {
        byte[] resultBytes = integerBytes(result);
        byte[] tsOidBytes = encodeOidValue(transferSyntaxOid);

        byte[] resultField = BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, false, 0, 0, resultBytes.length, resultBytes)
        );

        byte[] transferSyntaxField = BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, false, 1, 0, tsOidBytes.length, tsOidBytes)
        );

        byte[] itemValue = concat(List.of(resultField, transferSyntaxField));

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, itemValue.length, itemValue)
        );
    }

    private List<PresentationContextDefinition> parsePresentationContextDefinitions(BerTlv inboundListChild) {
        List<PresentationContextDefinition> out = new ArrayList<>();

        if (inboundListChild == null) {
            return out;
        }

        List<BerTlv> items;

        try {
            List<BerTlv> directItems = BerCodec.decodeAll(inboundListChild.value());

            if (directItems.size() == 1
                && directItems.get(0).tagClass() == TAG_CLASS_UNIVERSAL
                && directItems.get(0).constructed()
                && directItems.get(0).tagNumber() == 16) {

                BerTlv maybeWrapper = directItems.get(0);
                List<BerTlv> nested = BerCodec.decodeAll(maybeWrapper.value());

                boolean nestedAreItems = !nested.isEmpty();
                for (BerTlv nestedItem : nested) {
                    if (nestedItem.tagClass() != TAG_CLASS_UNIVERSAL
                        || !nestedItem.constructed()
                        || nestedItem.tagNumber() != 16) {
                        nestedAreItems = false;
                        break;
                    }
                }

                items = nestedAreItems ? nested : directItems;
            } else {
                items = directItems;
            }
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Failed to decode presentation context definition list", ex);
        }

        for (BerTlv item : items) {
            if (item.tagClass() != TAG_CLASS_UNIVERSAL || !item.constructed() || item.tagNumber() != 16) {
                throw new IllegalArgumentException("Presentation context definition item must be SEQUENCE");
            }

            List<BerTlv> fields = BerCodec.decodeAll(item.value());
            if (fields.size() < 3) {
                throw new IllegalArgumentException(
                    "Presentation context definition item must contain id, abstract syntax and transfer syntax list"
                );
            }

            BerTlv idField = fields.get(0);
            if (idField.tagClass() != TAG_CLASS_UNIVERSAL || idField.constructed() || idField.tagNumber() != 2) {
                throw new IllegalArgumentException("Presentation context id must be INTEGER");
            }

            int contextId = decodeSmallPositiveInteger(idField.value());

            BerTlv abstractSyntaxField = fields.get(1);
            if (abstractSyntaxField.tagClass() != TAG_CLASS_UNIVERSAL
                || abstractSyntaxField.constructed()
                || abstractSyntaxField.tagNumber() != 6) {
                throw new IllegalArgumentException("Presentation context abstract syntax must be OBJECT IDENTIFIER");
            }

            String abstractSyntaxOid = decodeOidValue(abstractSyntaxField.value());
            out.add(new PresentationContextDefinition(contextId, abstractSyntaxOid));
        }

        return out;
    }

    private byte[] buildPresentationPayloadChildFromInbound(BerTlv inboundPayloadChild, byte[] acseApdu) {
        if (acseApdu == null || acseApdu.length == 0) {
            return null;
        }

        try {
            if (inboundPayloadChild == null) {
                logger.warn("No inbound presentation payload child found; synthesizing fully-encoded-data");
                return buildPresentationUserDataFromAcse(acseApdu, 1);
            }

            byte[] inboundEncoded = BerCodec.encode(inboundPayloadChild);

            byte[] rebuiltCarrier = rebuildPresentationResponseCarrier(inboundPayloadChild, acseApdu);
            if (rebuiltCarrier != null) {
                logger.info(
                    "Inbound presentation payload child rebuilt as presentation carrier inbound-first-bytes={}",
                    toHexPreview(inboundEncoded, 128)
                );
                return rebuiltCarrier;
            }

            logger.info(
                "Presentation payload child fallback to synthesized fully-encoded-data inbound-first-bytes={}",
                toHexPreview(inboundEncoded, 128)
            );
            return buildPresentationUserDataFromAcse(acseApdu, 1);

        } catch (RuntimeException ex) {
            logger.warn("Failed to rebuild presentation payload child: {}", ex.getMessage(), ex);
            return buildPresentationUserDataFromAcse(acseApdu, 1);
        }
    }

    private byte[] rebuildPresentationResponseCarrier(BerTlv inboundPayloadChild, byte[] acseApdu) {
        if (inboundPayloadChild == null || acseApdu == null || acseApdu.length == 0) {
            return null;
        }

        try {
            byte[] inboundEncoded = BerCodec.encode(inboundPayloadChild);

            if (inboundPayloadChild.tagClass() == TAG_CLASS_APPLICATION
                && inboundPayloadChild.constructed()
                && inboundPayloadChild.tagNumber() == 1
                && !looksLikeTopLevelAcse(inboundEncoded)) {

                List<BerTlv> pdvItems = BerCodec.decodeAll(inboundPayloadChild.value());
                if (pdvItems.isEmpty()) {
                    return null;
                }

                List<byte[]> rebuiltItems = new ArrayList<>();
                boolean replaced = false;

                for (BerTlv pdvItem : pdvItems) {
                    byte[] rebuiltItem = rebuildPresentationPdvList(pdvItem, acseApdu);
                    if (rebuiltItem != null) {
                        rebuiltItems.add(rebuiltItem);
                        replaced = true;
                    } else {
                        rebuiltItems.add(BerCodec.encode(pdvItem));
                    }
                }

                if (replaced) {
                    byte[] rebuiltValue = concat(rebuiltItems);
                    return BerCodec.encode(
                        new BerTlv(TAG_CLASS_APPLICATION, true, 1, 0, rebuiltValue.length, rebuiltValue)
                    );
                }
            }

            return buildPresentationUserDataFromAcse(acseApdu, 1);

        } catch (RuntimeException ex) {
            logger.warn("Failed to rebuild presentation response carrier: {}", ex.getMessage(), ex);
            return buildPresentationUserDataFromAcse(acseApdu, 1);
        }
    }

    private byte[] rebuildPresentationPdvList(BerTlv pdvListNode, byte[] acseApdu) {
        if (pdvListNode == null || acseApdu == null || acseApdu.length == 0) {
            return null;
        }

        try {
            if (pdvListNode.tagClass() != TAG_CLASS_UNIVERSAL
                || !pdvListNode.constructed()
                || pdvListNode.tagNumber() != 16) {
                return null;
            }

            List<BerTlv> fields = BerCodec.decodeAll(pdvListNode.value());
            if (fields.isEmpty()) {
                return null;
            }

            List<byte[]> rebuiltFields = new ArrayList<>();
            boolean replaced = false;
            boolean sawContextId = false;

            for (BerTlv field : fields) {
                boolean isContextId =
                    field.tagClass() == TAG_CLASS_UNIVERSAL
                        && !field.constructed()
                        && field.tagNumber() == 2;

                boolean isPresentationDataValues =
                    field.tagClass() == TAG_CLASS_CONTEXT
                        && field.constructed()
                        && (field.tagNumber() == 0 || field.tagNumber() == 1 || field.tagNumber() == 2);

                if (isContextId) {
                    sawContextId = true;
                    rebuiltFields.add(BerCodec.encode(field));
                    continue;
                }

                if (isPresentationDataValues && !replaced) {
                    rebuiltFields.add(
                        BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, 0, 0, acseApdu.length, acseApdu))
                    );
                    replaced = true;
                    continue;
                }

                rebuiltFields.add(BerCodec.encode(field));
            }

            if (!replaced && sawContextId) {
                rebuiltFields.add(
                    BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, 0, 0, acseApdu.length, acseApdu))
                );
                replaced = true;
            }

            if (!replaced) {
                return null;
            }

            byte[] rebuiltValue = concat(rebuiltFields);

            return BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, rebuiltValue.length, rebuiltValue)
            );

        } catch (RuntimeException ex) {
            logger.debug("Failed to rebuild presentation PDV-list: {}", ex.getMessage());
            return null;
        }
    }

    private int decodeSmallPositiveInteger(byte[] value) {
        if (value == null || value.length == 0 || value.length > 4) {
            throw new IllegalArgumentException("Invalid INTEGER length");
        }

        if ((value[0] & 0x80) != 0) {
            throw new IllegalArgumentException("INTEGER must be non-negative");
        }

        int out = 0;
        for (byte b : value) {
            out = (out << 8) | (b & 0xFF);
        }

        if (out <= 0) {
            throw new IllegalArgumentException("Presentation-context-id must be positive");
        }

        return out;
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
                throw new IllegalArgumentException("OID arc must be >= 0");
            }
            writeBase128(out, arc);
        }

        return out.toByteArray();
    }

    private void writeBase128(ByteArrayOutputStream out, long value) {
        int[] tmp = new int[10];
        int count = 0;

        tmp[count++] = (int) (value & 0x7F);
        value >>= 7;

        while (value > 0) {
            tmp[count++] = (int) (value & 0x7F);
            value >>= 7;
        }

        for (int i = count - 1; i >= 0; i--) {
            int b = tmp[i];
            if (i != 0) {
                b |= 0x80;
            }
            out.write(b);
        }
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

    private byte[] concat(List<byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        if (parts == null) {
            return out.toByteArray();
        }

        for (byte[] part : parts) {
            if (part != null && part.length > 0) {
                out.write(part, 0, part.length);
            }
        }

        return out.toByteArray();
    }

    private boolean isRealAcseApdu(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);

            if (tlv.tagClass() != TAG_CLASS_APPLICATION || !tlv.constructed()) {
                return false;
            }

            int tag = tlv.tagNumber();
            if (tag < 0 || tag > 4) {
                return false;
            }

            return acseAssociationProtocol.decode(encoded) != null;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private byte[] extractSessionUserData(byte[] spdu) {
        if (spdu == null || spdu.length == 0) {
            return null;
        }

        logger.info(
            "session parse start si=0x{} li=0x{} totalLen={} first-bytes={}",
            toHexByte(spdu[0]),
            spdu.length > 1 ? toHexByte(spdu[1]) : "??",
            spdu.length,
            toHexPreview(spdu, 128)
        );

        /*
         * Special post-bind carrier observed in traces:
         *   01 00 01 03 19 01 03 <BER...>
         */
        if (looksLikePostBindSessionCarrier(spdu)) {
            if (spdu.length <= POST_BIND_SESSION_CARRIER_PREFIX_LEN) {
                logger.warn(
                    "P3 gateway post-bind session carrier too short len={} first-bytes={}",
                    spdu.length,
                    toHexPreview(spdu, 64)
                );
                return null;
            }

            byte[] value = Arrays.copyOfRange(spdu, POST_BIND_SESSION_CARRIER_PREFIX_LEN, spdu.length);
            logger.info(
                "P3 gateway post-bind session carrier extracted payload offset={} len={} first-bytes={}",
                POST_BIND_SESSION_CARRIER_PREFIX_LEN,
                value.length,
                toHexPreview(value, 192)
            );
            return value;
        }

        /*
         * Short session parameter carrier:
         *   09 <LI> ... C1 <len> <payload>
         */
        if (looksLikeShortSessionParameterCarrier(spdu)) {
            int index = 2;
            while (index + 1 < spdu.length) {
                int pi = spdu[index] & 0xFF;
                int li = spdu[index + 1] & 0xFF;
                int valueStart = index + 2;
                int valueEnd = valueStart + li;

                if (valueEnd > spdu.length) {
                    logger.warn(
                        "P3 gateway short session carrier truncated: pi=0x{} li={}",
                        toHexByte((byte) pi),
                        li
                    );
                    return null;
                }

                if (pi == 0xC1 || pi == 0xC0 || pi == 0xC2) {
                    byte[] value = Arrays.copyOfRange(spdu, valueStart, valueEnd);
                    logger.info(
                        "P3 gateway short session carrier extracted payload pi=0x{} offset={} len={} first-bytes={}",
                        toHexByte((byte) pi),
                        index,
                        value.length,
                        toHexPreview(value, 192)
                    );
                    return value;
                }

                index = valueEnd;
            }

            logger.warn("P3 gateway short session carrier had no user-data parameter");
            return null;
        }

        int start = sessionParameterStart(spdu);
        if (start >= 0) {
            int index = start;
            while (index + 1 < spdu.length) {
                int pi = spdu[index] & 0xFF;
                int li1 = spdu[index + 1] & 0xFF;

                logger.info(
                    "session param scan index={} pi=0x{} li1=0x{} remaining={}",
                    index,
                    toHexByte((byte) pi),
                    toHexByte((byte) li1),
                    spdu.length - index
                );

                int valueStart;
                int valueLength;

                if (li1 == 0xFF) {
                    if (index + 3 >= spdu.length) {
                        logger.warn(
                            "P3 gateway extended session parameter length truncated: pi=0x{}",
                            toHexByte((byte) pi)
                        );
                        break;
                    }
                    valueLength = ((spdu[index + 2] & 0xFF) << 8) | (spdu[index + 3] & 0xFF);
                    valueStart = index + 4;
                } else {
                    valueLength = li1;
                    valueStart = index + 2;
                }

                int valueEnd = valueStart + valueLength;
                if (valueEnd > spdu.length) {
                    logger.warn(
                        "P3 gateway session parameter truncated: pi=0x{} li={}",
                        toHexByte((byte) pi),
                        valueLength
                    );
                    break;
                }

                byte[] value = Arrays.copyOfRange(spdu, valueStart, valueEnd);
                if (pi == 0xC1 || pi == 0xC0 || pi == 0xC2) {
                    logger.info(
                        "P3 gateway session found SPDU parameter pi=0x{} offset={} li={} first-bytes={}",
                        toHexByte((byte) pi),
                        index,
                        valueLength,
                        toHexPreview(value, 192)
                    );
                    return value;
                }

                index = valueEnd;
            }
        }

        byte[] embedded = findEmbeddedAsn1Payload(spdu);
        if (embedded != null) {
            logger.info(
                "P3 gateway session fallback embedded ASN.1 payload first-bytes={}",
                toHexPreview(embedded, 192)
            );
            return embedded;
        }

        logger.warn("P3 gateway session could not extract user-data payload");
        return null;
    }

    private byte[] findEmbeddedAsn1Payload(byte[] data) {
        if (data == null || data.length < 2) {
            return null;
        }

        int offset = locateEmbeddedAsn1Offset(data);
        if (offset < 0) {
            return null;
        }

        try {
            byte[] candidate = Arrays.copyOfRange(data, offset, data.length);
            BerTlv tlv = BerCodec.decodeSingle(candidate);
            int totalLength = tlv.headerLength() + tlv.length();

            if (totalLength <= 0 || offset + totalLength > data.length) {
                return null;
            }

            byte[] selected = Arrays.copyOfRange(data, offset, offset + totalLength);

            logger.info(
                "P3 gateway embedded ASN.1 payload chosen offset={} len={} first-bytes={}",
                offset,
                selected.length,
                toHexPreview(selected, 192)
            );

            return selected;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private boolean looksLikeShortSessionParameterCarrier(byte[] spdu) {
        if (spdu == null || spdu.length < 6) {
            return false;
        }

        if ((spdu[0] & 0xFF) != 0x09) {
            return false;
        }

        int li = spdu[1] & 0xFF;
        if (li == 0xFF || li + 2 != spdu.length) {
            return false;
        }

        int index = 2;
        boolean foundUserData = false;

        while (index + 1 < spdu.length) {
            int pi = spdu[index] & 0xFF;
            int pli = spdu[index + 1] & 0xFF;

            int valueStart = index + 2;
            int valueEnd = valueStart + pli;
            if (valueEnd > spdu.length) {
                return false;
            }

            if (pi == 0xC1 || pi == 0xC0 || pi == 0xC2) {
                foundUserData = true;
            }

            index = valueEnd;
        }

        return foundUserData && index == spdu.length;
    }

    private byte[] replaceSessionUserDataByParameters(byte[] spdu, byte[] newValue) {
        if (spdu == null || spdu.length < 4 || newValue == null) {
            return null;
        }

        if (looksLikePostBindSessionCarrier(spdu) || looksLikeShortSessionParameterCarrier(spdu)) {
            logger.info("Skipping generic PI/LI session rebuild for special session carrier");
            return null;
        }

        int start = sessionParameterStart(spdu);
        if (start < 0) {
            return null;
        }

        List<SessionParameter> params;
        try {
            params = parseSessionParameters(spdu, start);
        } catch (RuntimeException ex) {
            logger.warn("Could not rebuild session SPDU via PI/LI parameters: {}", ex.getMessage());
            return null;
        }

        if (params.isEmpty()) {
            return null;
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        boolean replaced = false;

        for (SessionParameter param : params) {
            byte[] value = param.value();
            if (param.pi() == 0xC1 || param.pi() == 0xC0 || param.pi() == 0xC2) {
                value = newValue;
                replaced = true;
            }
            writeSessionParameter(body, param.pi(), value);
        }

        if (!replaced) {
            return null;
        }

        byte[] bodyBytes = body.toByteArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(mapSessionResponseCode(spdu[0]));
        out.write(0xFF);
        out.write((bodyBytes.length >> 8) & 0xFF);
        out.write(bodyBytes.length & 0xFF);
        out.writeBytes(bodyBytes);

        byte[] rebuilt = out.toByteArray();

        logger.info(
            "P3 session rebuilt via parameter replacement len={} first-bytes={}",
            rebuilt.length,
            toHexPreview(rebuilt, 192)
        );

        return rebuilt;
    }
    
    private byte[] rebuildShortSessionParameterCarrier(byte[] inboundSpdu, byte[] newPayload) {
        if (inboundSpdu == null || newPayload == null || !looksLikeShortSessionParameterCarrier(inboundSpdu)) {
            return null;
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();

        int index = 2;
        boolean replaced = false;

        while (index + 1 < inboundSpdu.length) {
            int pi = inboundSpdu[index] & 0xFF;
            int li = inboundSpdu[index + 1] & 0xFF;
            int valueStart = index + 2;
            int valueEnd = valueStart + li;

            if (valueEnd > inboundSpdu.length) {
                return null;
            }

            byte[] value = Arrays.copyOfRange(inboundSpdu, valueStart, valueEnd);
            if (pi == 0xC1 || pi == 0xC0 || pi == 0xC2) {
                value = newPayload;
                replaced = true;
            }

            writeSessionParameter(body, pi, value);
            index = valueEnd;
        }

        if (!replaced) {
            return null;
        }

        byte[] bodyBytes = body.toByteArray();
        if (bodyBytes.length > 255) {
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(inboundSpdu[0] & 0xFF);   // 0x09
        out.write(bodyBytes.length & 0xFF); // short LI
        out.writeBytes(bodyBytes);
        return out.toByteArray();
    }

    private int locateEmbeddedAsn1Offset(byte[] data) {
        if (data == null || data.length < 2) {
            return -1;
        }

        int bestOffset = -1;
        int bestScore = Integer.MIN_VALUE;

        for (int i = 0; i < data.length - 1; i++) {
            try {
                byte[] candidate = Arrays.copyOfRange(data, i, data.length);
                BerTlv tlv = BerCodec.decodeSingle(candidate);
                int totalLength = tlv.headerLength() + tlv.length();

                if (totalLength <= 0 || i + totalLength > data.length) {
                    continue;
                }

                byte[] encoded = Arrays.copyOfRange(data, i, i + totalLength);

                int score = scoreEmbeddedAsn1Candidate(tlv, encoded, i, data.length);
                if (score > bestScore) {
                    bestScore = score;
                    bestOffset = i;
                }
            } catch (RuntimeException ignored) {
            }
        }

        if (bestOffset >= 0) {
            logger.info("P3 gateway selected embedded ASN.1 payload offset={} score={}", bestOffset, bestScore);
        }

        return bestOffset;
    }
    
    private int scoreEmbeddedAsn1Candidate(BerTlv tlv, byte[] encoded, int offset, int containerLength) {
        if (tlv == null || encoded == null || encoded.length == 0) {
            return Integer.MIN_VALUE;
        }

        int score = 0;

        // Strongly prefer candidates closer to the front.
        score -= offset;

        // Prefer larger candidates.
        score += Math.min(encoded.length, 4096);

        // Strongly prefer top-level application constructed nodes.
        if (tlv.tagClass() == TAG_CLASS_APPLICATION && tlv.constructed()) {
            score += 5000;
        }

        // Prefer ACSE if it really decodes.
        if (looksLikeTopLevelAcse(encoded)) {
            score += 4000;
        }

        // Prefer known P3 APDUs.
        if (p3ProtocolCodec.isSupportedApplicationApdu(encoded)) {
            score += 3500;
        }

        // Prefer known P22 APDUs.
        if (p22ProtocolCodec.isSupportedApplicationApdu(encoded)) {
            score += 3000;
        }

        // Prefer Presentation root.
        if (tlv.tagClass() == TAG_CLASS_UNIVERSAL && tlv.constructed() && tlv.tagNumber() == 17) {
            score += 2500;
        }

        // Penalize tiny inner fragments heavily.
        if (encoded.length < 16) {
            score -= 5000;
        }

        // Penalize context-specific fragments unless they are also recognized.
        if (tlv.tagClass() == TAG_CLASS_CONTEXT) {
            score -= 1500;
        }

        // High-tag-number context-specific tiny fields like BF 02 01 01 are almost never the real app PDU here.
        if (tlv.tagClass() == TAG_CLASS_CONTEXT && encoded.length < 32) {
            score -= 3000;
        }
        
        // Absolute reject tiny nodes
        if (encoded.length < 12) {
            return Integer.MIN_VALUE;
        }

        return score;
    }

    private List<SessionParameter> parseSessionParameters(byte[] spdu, int start) {
        List<SessionParameter> params = new ArrayList<>();
        int index = start;

        while (index + 1 < spdu.length) {
            int pi = spdu[index] & 0xFF;
            int li1 = spdu[index + 1] & 0xFF;

            int valueStart;
            int valueLength;

            if (li1 == 0xFF) {
                if (index + 3 >= spdu.length) {
                    throw new IllegalArgumentException(
                        "Invalid extended session parameter length: pi=0x" + toHexByte((byte) pi)
                    );
                }
                valueLength = ((spdu[index + 2] & 0xFF) << 8) | (spdu[index + 3] & 0xFF);
                valueStart = index + 4;
            } else {
                valueLength = li1;
                valueStart = index + 2;
            }

            int valueEnd = valueStart + valueLength;
            if (valueEnd > spdu.length) {
                throw new IllegalArgumentException(
                    "Invalid session parameter bounds: pi=0x" + toHexByte((byte) pi) + " li=" + valueLength
                );
            }

            params.add(new SessionParameter(pi, Arrays.copyOfRange(spdu, valueStart, valueEnd)));
            index = valueEnd;
        }

        return params;
    }

    private void writeSessionParameter(ByteArrayOutputStream out, int pi, byte[] value) {
        if (value == null) {
            value = new byte[0];
        }
        if (value.length > 65_535) {
            throw new IllegalArgumentException(
                "Session parameter too large: pi=0x" + toHexByte((byte) pi) + " len=" + value.length
            );
        }

        out.write(pi & 0xFF);

        if (value.length <= 254) {
            out.write(value.length & 0xFF);
        } else {
            out.write(0xFF);
            out.write((value.length >> 8) & 0xFF);
            out.write(value.length & 0xFF);
        }

        out.writeBytes(value);
    }

    private int sessionParameterStart(byte[] spdu) {
        if (spdu == null || spdu.length < 2) {
            return -1;
        }

        if (looksLikePostBindSessionCarrier(spdu) || looksLikeShortSessionParameterCarrier(spdu)) {
            return -1;
        }

        int si = spdu[0] & 0xFF;
        if (si != 0x0D && si != 0x01 && si != 0x0E && si != 0x19) {
            return -1;
        }

        int li = spdu[1] & 0xFF;
        if (li == 0xFF) {
            return spdu.length >= 4 ? 4 : -1;
        }
        return 2;
    }
    
    private static final int POST_BIND_SESSION_CARRIER_PREFIX_LEN = 7;

    private boolean looksLikePostBindSessionCarrier(byte[] spdu) {
        return spdu != null
            && spdu.length >= POST_BIND_SESSION_CARRIER_PREFIX_LEN + 2
            && (spdu[0] & 0xFF) == 0x01
            && (spdu[1] & 0xFF) == 0x00
            && (spdu[2] & 0xFF) == 0x01
            && (spdu[3] & 0xFF) == 0x03
            && (spdu[4] & 0xFF) == 0x19
            && (spdu[5] & 0xFF) == 0x01
            && (spdu[6] & 0xFF) == 0x03;
    }

    private byte[] rebuildPostBindSessionCarrier(byte[] inboundSpdu, byte[] newPayload) {
        if (!looksLikePostBindSessionCarrier(inboundSpdu) || newPayload == null) {
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(Arrays.copyOf(inboundSpdu, POST_BIND_SESSION_CARRIER_PREFIX_LEN));
        out.writeBytes(newPayload);
        return out.toByteArray();
    }

    private byte[] unwrapPresentation(byte[] ppdu) {
        try {
            BerTlv root = BerCodec.decodeSingle(ppdu);

            if (root.tagClass() != TAG_CLASS_UNIVERSAL || !root.constructed() || root.tagNumber() != 17) {
                logger.debug("unwrapPresentation: not a presentation PPDU");
                return null;
            }

            logger.info("P3 gateway presentation root first-bytes={}", toHexPreview(ppdu, 192));

            List<Integer> path = findPresentationPayloadPath(root);
            if (path == null) {
                logger.info("P3 gateway presentation unwrap result len=-1 first-bytes=<null>");
                return null;
            }

            byte[] payload = extractNodeAtPath(root, path);
            logger.info(
                "P3 gateway presentation selected nested payload path={} len={} first-bytes={}",
                path,
                payload == null ? -1 : payload.length,
                payload == null ? "<null>" : toHexPreview(payload, 128)
            );
            return payload;
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap presentation PPDU: {}", ex.getMessage());
            return null;
        }
    }

    private List<Integer> findPresentationPayloadPath(BerTlv root) {
        try {
            List<BerTlv> children = BerCodec.decodeAll(root.value());

            logger.info(
                "P3 gateway presentation root children count={} first-bytes={}",
                children.size(),
                toHexPreview(BerCodec.encode(root), 192)
            );

            for (int i = 0; i < children.size(); i++) {
                BerTlv child = children.get(i);
                byte[] childEncoded = BerCodec.encode(child);

                logger.info(
                    "P3 gateway presentation child[{}] tagClass={} constructed={} tagNumber={} len={} first-bytes={}",
                    i,
                    child.tagClass(),
                    child.constructed(),
                    child.tagNumber(),
                    child.length(),
                    toHexPreview(childEncoded, 128)
                );

                if (isTinyPresentationControl(child)) {
                    logger.info("P3 gateway presentation child[{}] skipped as tiny control fragment", i);
                    continue;
                }

                List<Integer> nested = findPayloadPathInNode(child);
                if (nested != null) {
                    List<Integer> full = new ArrayList<>();
                    full.add(i);
                    full.addAll(nested);
                    return full;
                }
            }

            return null;
        } catch (RuntimeException ex) {
            logger.debug("findPresentationPayloadPath failed: {}", ex.getMessage());
            return null;
        }
    }

    private List<Integer> findPayloadPathInNode(BerTlv node) {
        if (node == null) {
            return null;
        }

        if (isTinyPresentationControl(node)) {
            return null;
        }

        byte[] encoded;
        try {
            encoded = BerCodec.encode(node);
        } catch (RuntimeException ex) {
            return null;
        }

        if (isRealAcseApdu(encoded)) {
            return new ArrayList<>();
        }

        if (node.constructed()) {
            try {
                List<BerTlv> children = BerCodec.decodeAll(node.value());

                for (int i = 0; i < children.size(); i++) {
                    List<Integer> nested = findPayloadPathInNode(children.get(i));
                    if (nested != null) {
                        List<Integer> full = new ArrayList<>();
                        full.add(i);
                        full.addAll(nested);
                        return full;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        if (!node.constructed() || isDirectNativeP3ApduCandidate(node)) {
            if (p3ProtocolCodec.isSupportedApplicationApdu(encoded)) {
                return new ArrayList<>();
            }
        }

        return null;
    }

    private boolean isDirectNativeP3ApduCandidate(BerTlv node) {
        return node != null
            && node.tagClass() == TAG_CLASS_CONTEXT
            && node.constructed()
            && node.tagNumber() >= 0
            && node.tagNumber() <= 17;
    }

    
    private byte[] extractNodeAtPath(BerTlv root, List<Integer> path) {
        BerTlv current = root;

        for (Integer index : path) {
            List<BerTlv> children = BerCodec.decodeAll(current.value());
            if (index < 0 || index >= children.size()) {
                return null;
            }
            current = children.get(index);
        }

        return BerCodec.encode(current);
    }

    private boolean isTinyPresentationControl(BerTlv tlv) {
        if (tlv == null) {
            return false;
        }

        byte[] encoded = BerCodec.encode(tlv);

        if (encoded.length == 5
            && (encoded[0] & 0xFF) == 0xA0
            && (encoded[1] & 0xFF) == 0x03
            && (encoded[2] & 0xFF) == 0x80
            && (encoded[3] & 0xFF) == 0x01
            && (encoded[4] & 0xFF) == 0x01) {
            return true;
        }

        if (encoded.length <= 8) {
            return true;
        }

        if (tlv.tagClass() == TAG_CLASS_CONTEXT && tlv.constructed()) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
                if (nested.size() == 1) {
                    byte[] child = BerCodec.encode(nested.get(0));
                    if (child.length <= 8) {
                        return true;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        return false;
    }

    private byte[] unwrapAcse(byte[] acseApdu) {
        if (acseApdu == null || acseApdu.length == 0) {
            return null;
        }

        try {
            BerTlv acse = BerCodec.decodeSingle(acseApdu);

            byte[] strict = unwrapAcseNode(acse);
            if (strict != null && strict.length > 0) {
                return strict;
            }

            byte[] embedded = findEmbeddedRoseOrApplication(acse);
            if (embedded != null && embedded.length > 0) {
                return embedded;
            }

            // Fallback: keep the ACSE APDU itself
            return acseApdu;
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap ACSE APDU: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] findEmbeddedRoseOrApplication(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            byte[] encoded = BerCodec.encode(node);

            if (p22ProtocolCodec.isSupportedApplicationApdu(encoded)) {
                return encoded;
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    byte[] found = findEmbeddedRoseOrApplication(child);
                    if (found != null) {
                        return found;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private byte[] unwrapAcseNode(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            if (node.tagClass() == TAG_CLASS_CONTEXT && node.tagNumber() == 30) {
                return unwrapAcseUserInformation(node);
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    byte[] found = unwrapAcseNode(child);
                    if (found != null) {
                        return found;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private byte[] unwrapAcseUserInformation(BerTlv userInfoField) {
        if (userInfoField == null || userInfoField.value().length == 0) {
            return null;
        }

        try {
            BerTlv external = BerCodec.decodeSingle(userInfoField.value());

            if (external.tagClass() != TAG_CLASS_UNIVERSAL || external.tagNumber() != 8) {
                return null;
            }

            List<BerTlv> externalElements = BerCodec.decodeAll(external.value());

            for (BerTlv element : externalElements) {
                if (element.tagClass() == TAG_CLASS_CONTEXT && element.tagNumber() == 0) {
                    if (!element.constructed() || element.value().length == 0) {
                        return null;
                    }

                    // Return embedded payload only, not encoded A0 wrapper
                    return element.value();
                }
            }
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap ACSE user-information: {}", ex.getMessage());
        }

        return null;
    }

    private byte[] wrapAcseEnvelope(byte[] rosPayload, byte[] inboundAcse) {
        logger.info(
            "P3 ACSE wrapping ROS payload len={} inbound-acse-first-bytes={}",
            rosPayload == null ? -1 : rosPayload.length,
            inboundAcse == null ? "<null>" : toHexPreview(inboundAcse, 192)
        );

        if (rosPayload != null && looksLikeTopLevelAcse(rosPayload)) {
            return rosPayload;
        }

        Optional<String> applicationContextName = Optional.empty();

        try {
            if (inboundAcse != null && inboundAcse.length > 0) {
                applicationContextName = extractApplicationContextNameFromAarq(inboundAcse);

                Optional<AcseModels.AcseApdu> decoded = tryDecodeAcse(inboundAcse);
                if (decoded.isPresent()) {
                    AcseModels.AcseApdu apdu = decoded.get();

                    if (apdu instanceof AcseModels.AARQApdu) {
                        AcseModels.AAREApdu aare = new AcseModels.AAREApdu(
                            applicationContextName,
                            true,
                            Optional.empty(),
                            Optional.of(new AcseModels.ResultSourceDiagnostic(1, 0)),
                            Optional.empty(),
                            Optional.empty(),
                            Optional.empty(),
                            Optional.ofNullable(rosPayload),
                            List.of(),
                            java.util.Set.of()
                        );

                        byte[] encoded = acseAssociationProtocol.encode(aare);
                        logger.info(
                            "P3 ACSE built AARE len={} first-bytes={}",
                            encoded.length,
                            toHexPreview(encoded, 192)
                        );
                        return encoded;
                    }

                    if (apdu instanceof AcseModels.RLRQApdu) {
                        AcseModels.RLREApdu rlre = new AcseModels.RLREApdu(true);
                        byte[] encoded = acseAssociationProtocol.encode(rlre);
                        logger.info(
                            "P3 ACSE built RLRE len={} first-bytes={}",
                            encoded.length,
                            toHexPreview(encoded, 192)
                        );
                        return encoded;
                    }
                }
            }
        } catch (RuntimeException ex) {
            logger.warn("Failed to inspect inbound ACSE APDU: {}", ex.getMessage(), ex);
        }

        AcseModels.AAREApdu fallback = new AcseModels.AAREApdu(
            applicationContextName,
            true,
            Optional.empty(),
            Optional.of(new AcseModels.ResultSourceDiagnostic(1, 0)),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.ofNullable(rosPayload),
            List.of(),
            java.util.Set.of()
        );

        byte[] encoded = acseAssociationProtocol.encode(fallback);
        logger.info(
            "P3 ACSE built fallback AARE len={} first-bytes={}",
            encoded.length,
            toHexPreview(encoded, 192)
        );
        return encoded;
    }

    private Optional<AcseModels.AcseApdu> tryDecodeAcse(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return Optional.empty();
        }

        try {
            return Optional.ofNullable(acseAssociationProtocol.decode(encoded));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    private boolean looksLikeTopLevelAcse(byte[] encoded) {
    	if (encoded == null || encoded.length < 8) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);

            if (tlv.tagClass() != TAG_CLASS_APPLICATION || !tlv.constructed()) {
                return false;
            }

            int tag = tlv.tagNumber();
            if (tag < 0 || tag > 4) {
                return false;
            }

            if (looksLikePresentationFullyEncodedData(tlv)) {
                return false;
            }

            if (!containsAcseLikeFields(tlv)) {
                return false;
            }

            return true;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean looksLikePresentationFullyEncodedData(BerTlv tlv) {
        if (tlv == null
            || tlv.tagClass() != TAG_CLASS_APPLICATION
            || !tlv.constructed()
            || tlv.tagNumber() != 1) {
            return false;
        }

        try {
            List<BerTlv> pdvItems = BerCodec.decodeAll(tlv.value());
            if (pdvItems.isEmpty()) {
                return false;
            }

            for (BerTlv item : pdvItems) {
                if (item.tagClass() != TAG_CLASS_UNIVERSAL
                    || !item.constructed()
                    || item.tagNumber() != 16) {
                    return false;
                }

                List<BerTlv> fields = BerCodec.decodeAll(item.value());
                if (fields.isEmpty()) {
                    return false;
                }

                boolean hasContextId = false;
                boolean hasPresentationDataValues = false;

                for (BerTlv field : fields) {
                    if (field.tagClass() == TAG_CLASS_UNIVERSAL
                        && !field.constructed()
                        && field.tagNumber() == 2) {
                        hasContextId = true;
                    }

                    if (field.tagClass() == TAG_CLASS_CONTEXT
                        && field.constructed()
                        && (field.tagNumber() == 0 || field.tagNumber() == 1 || field.tagNumber() == 2)) {
                        hasPresentationDataValues = true;
                    }
                }

                if (hasContextId && hasPresentationDataValues) {
                    return true;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return false;
    }

    private boolean containsAcseLikeFields(BerTlv tlv) {
        if (tlv == null || !tlv.constructed()) {
            return false;
        }

        try {
            List<BerTlv> fields = BerCodec.decodeAll(tlv.value());
            if (fields.isEmpty()) {
                return false;
            }

            for (BerTlv field : fields) {
                if (field.tagClass() == TAG_CLASS_CONTEXT) {
                    int n = field.tagNumber();
                    if (n == 0 || n == 1 || n == 2 || n == 3 || n == 4 || n == 30) {
                        return true;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return false;
    }

    private Optional<String> extractApplicationContextNameFromAarq(byte[] inboundAcse) {
        if (inboundAcse == null || inboundAcse.length == 0) {
            return Optional.empty();
        }

        try {
            BerTlv aarq = BerCodec.decodeSingle(inboundAcse);
            if (aarq.tagClass() != TAG_CLASS_APPLICATION || !aarq.constructed() || aarq.tagNumber() != 0) {
                return Optional.empty();
            }

            List<BerTlv> fields = BerCodec.decodeAll(aarq.value());
            return BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1).map(field -> {
                BerTlv oid = BerCodec.decodeSingle(field.value());
                if (!oid.isUniversal() || oid.tagNumber() != 6) {
                    throw new IllegalArgumentException("AARQ application-context-name is not an OBJECT IDENTIFIER");
                }
                return decodeOidValue(oid.value());
            });
        } catch (RuntimeException ex) {
            logger.debug("Failed to extract AARQ application-context-name: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    private String decodeOidValue(byte[] oidBytes) {
        if (oidBytes == null || oidBytes.length == 0) {
            throw new IllegalArgumentException("BER OBJECT IDENTIFIER is empty");
        }

        int first = oidBytes[0] & 0xFF;
        int firstArc = Math.min(first / 40, 2);
        int secondArc = first - (firstArc * 40);

        StringBuilder oid = new StringBuilder();
        oid.append(firstArc).append('.').append(secondArc);

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

    private byte mapSessionResponseCode(byte inboundCode) {
        return (byte) (((inboundCode & 0xFF) == 0x0D) ? 0x0E : inboundCode);
    }

    private String commandName(String line) {
        String trimmed = line == null ? "" : line.trim();
        if (trimmed.isEmpty()) {
            return "<blank>";
        }
        int separator = trimmed.indexOf(' ');
        return separator < 0 ? trimmed : trimmed.substring(0, separator);
    }

    private String toHexByte(byte value) {
        return String.format("%02X", value & 0xFF);
    }

    private String toHex(byte[] bytes) {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                value.append(' ');
            }
            value.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return value.toString();
    }

    private String toHexPreview(byte[] bytes, int maxBytes) {
        if (bytes == null) {
            return "<null>";
        }
        if (bytes.length <= maxBytes) {
            return toHex(bytes);
        }
        return toHex(Arrays.copyOf(bytes, maxBytes)) + " ...";
    }

    private enum ProtocolKind {
        TEXT_COMMAND,
        BER_APDU,
        RFC1006_TPKT,
        TLS_CLIENT_HELLO,
        UNKNOWN_BINARY
    }

    private enum ListenerProfile {
        STANDARD_P3,
        GATEWAY_MULTI_PROTOCOL;

        private static ListenerProfile from(String value) {
            if (value == null || value.isBlank()) {
                return STANDARD_P3;
            }
            try {
                return ListenerProfile.valueOf(value.trim().toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException(
                    "Invalid amhs.p3.gateway.listener-profile value '" + value
                        + "'. Supported values: STANDARD_P3, GATEWAY_MULTI_PROTOCOL"
                );
            }
        }

        private boolean supports(ProtocolKind protocolKind) {
            if (this == GATEWAY_MULTI_PROTOCOL) {
                return protocolKind == ProtocolKind.BER_APDU || protocolKind == ProtocolKind.RFC1006_TPKT;
            }
            return protocolKind == ProtocolKind.RFC1006_TPKT;
        }

        private String supportedProtocolsSummary() {
            if (this == GATEWAY_MULTI_PROTOCOL) {
                return "BER_APDU, RFC1006_TPKT";
            }
            return "RFC1006_TPKT";
        }
    }

    private record CotpFrame(byte type, boolean endOfTsdu, byte[] userData, byte[] payload) {}
    private record SessionParameter(int pi, byte[] value) {}
    private record PresentationContextDefinition(int presentationContextId, String abstractSyntaxOid) {}

    private static final class NamedDaemonThreadFactory implements ThreadFactory {
        private int counter = 0;

        @Override
        public synchronized Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "amhs-p3-gateway-client-" + (++counter));
            thread.setDaemon(true);
            return thread;
        }
    }
}