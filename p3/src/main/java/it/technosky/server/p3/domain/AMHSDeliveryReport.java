package it.technosky.server.p3.domain;

import java.util.Date;
import java.util.HexFormat;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class AMHSDeliveryReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "message_id_fk", nullable = false)
    private AMHSMessage message;

    @Column(name = "recipient", nullable = false, length = 1024)
    private String recipient;

    @Enumerated(EnumType.STRING)
    @Column(name = "report_type", nullable = false, length = 8)
    private AMHSReportType reportType;

    @Enumerated(EnumType.STRING)
    @Column(name = "delivery_status", nullable = false, length = 16)
    private AMHSDeliveryStatus deliveryStatus;

    @Column(name = "x411_diagnostic_code", length = 64)
    private String x411DiagnosticCode;

    @Column(name = "non_delivery_reason", length = 128)
    private String nonDeliveryReason;


    @Column(name = "related_mts_identifier", length = 255)
    private String relatedMtsIdentifier;

    @Column(name = "correlation_token", length = 255)
    private String correlationToken;

    @Column(name = "return_of_content", nullable = false)
    private boolean returnOfContent;

    @Column(name = "expires_at")
    @Temporal(TemporalType.TIMESTAMP)
    private Date expiresAt;


    @Column(name = "ndr_apdu_raw_ber", length = 8192)
    private String ndrApduRawBerHex;

    @Column(name = "ndr_apdu_tag_class")
    private Integer ndrApduTagClass;

    @Column(name = "ndr_apdu_tag_number")
    private Integer ndrApduTagNumber;

    @Column(name = "generated_at", nullable = false, updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date generatedAt;

    public void setNdrApduRawBer(byte[] apdu) {
        if (apdu == null || apdu.length == 0) {
            this.ndrApduRawBerHex = null;
            return;
        }
        this.ndrApduRawBerHex = HexFormat.of().formatHex(apdu);
    }

    @PrePersist
    protected void onCreate() {
        if (generatedAt == null) {
            generatedAt = new Date();
        }
    }
}
