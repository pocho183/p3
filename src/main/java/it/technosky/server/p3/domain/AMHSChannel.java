package it.technosky.server.p3.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class AMHSChannel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true, length = 64)
    private String name;
    @Column(name = "expected_cn", length = 255)
    private String expectedCn;
    @Column(name = "expected_ou", length = 255)
    private String expectedOu;
    @Column(nullable = false)
    private boolean enabled = true;
}
