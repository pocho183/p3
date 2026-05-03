package it.technosky.server.p3.domain;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.address.ORAddress;

@Component
public class AMHSComplianceValidator {

    //private static final Pattern ICAO_8_CHAR = Pattern.compile("^[A-Z]{8}$");
    private static final Pattern ICAO_8_CHAR = Pattern.compile("^[A-Z]{4,8}$");
    private static final Pattern NUMERIC_COUNTRY = Pattern.compile("^\\d{3}$");
    private static final Set<String> ISO_COUNTRIES = Set.of(Locale.getISOCountries());

    public void validate(String from, String to, String body, AMHSProfile profile) {
        if (!StringUtils.hasText(body) || body.length() > 100_000) {
            throw new IllegalArgumentException("Invalid AMHS body size");
        }

        validateAddress(from, "from");
        validateAddress(to, "to");

        if (profile == null) {
            throw new IllegalArgumentException("AMHS profile is mandatory");
        }
    }

    public void validateIcaoOrAddress(String address, String fieldName) {
        validateAddress(address, fieldName);
    }

    public void validateCertificateIdentity(AMHSChannel channel, String certificateCn, String certificateOu) {
        if (!StringUtils.hasText(certificateCn) && !StringUtils.hasText(certificateOu)) {
            return;
        }

        if (StringUtils.hasText(channel.getExpectedCn())) {
            if (!StringUtils.hasText(certificateCn) || !channel.getExpectedCn().equalsIgnoreCase(certificateCn.trim())) {
                throw new IllegalArgumentException("Certificate CN does not match channel policy");
            }
        }

        if (StringUtils.hasText(channel.getExpectedOu())) {
            if (!StringUtils.hasText(certificateOu) || !channel.getExpectedOu().equalsIgnoreCase(certificateOu.trim())) {
                throw new IllegalArgumentException("Certificate OU does not match channel policy");
            }
        }
    }

    public void validateOrAddressBinding(String from, String certificateCn, String certificateOu) {
        if (!StringUtils.hasText(certificateCn) && !StringUtils.hasText(certificateOu)) {
            return;
        }

        String icaoUnit = extractIcaoUnit(from);
        String normalizedCn = normalized(certificateCn);
        String normalizedOu = normalized(certificateOu);

        if (!icaoUnit.equals(normalizedCn) && !icaoUnit.equals(normalizedOu)) {
            throw new IllegalArgumentException("Certificate subject is not bound to sender O/R address ICAO unit");
        }
    }

    public void validateAuthenticatedIdentityBinding(String from, String authenticatedIdentity) {
        if (!StringUtils.hasText(authenticatedIdentity)) {
            return;
        }

        String normalizedIdentity = normalized(authenticatedIdentity);
        String senderIcaoUnit = extractIcaoUnit(from);
        String senderCn = "";
        String normalizedAddress = from.trim().toUpperCase(Locale.ROOT);
        if (!ICAO_8_CHAR.matcher(normalizedAddress).matches()) {
            senderCn = normalized(ORAddress.parse(normalizedAddress).get("CN"));
        }

        if (!normalizedIdentity.equals(senderIcaoUnit) && !normalizedIdentity.equals(senderCn)) {
            throw new IllegalArgumentException("Authenticated identity is not bound to sender O/R address");
        }
    }

    private void validateAddress(String address, String fieldName) {
        if (!StringUtils.hasText(address)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " address is mandatory");
        }

        String normalized = address.trim().toUpperCase(Locale.ROOT);

        if (ICAO_8_CHAR.matcher(normalized).matches()) {
            return;
        }

        ORAddress orAddress = ORAddress.parse(normalized);

        String country = normalized(orAddress.get("C"));
        String admd = normalized(orAddress.get("ADMD"));
        String prmd = normalized(orAddress.get("PRMD"));
        String organization = normalized(orAddress.get("O"));

        if (!ISO_COUNTRIES.contains(country) && !NUMERIC_COUNTRY.matcher(country).matches()) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include a valid ISO country code");
        }
        if (!"ICAO".equals(admd)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include ADMD/A=ICAO");
        }
        if (!StringUtils.hasText(prmd)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include PRMD/P");
        }
        if (!StringUtils.hasText(organization)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include O");
        }

        if (orAddress.organizationalUnits().isEmpty()) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include at least OU1");
        }

        if (!containsIcaoUnit(orAddress)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must contain an 8-letter ICAO unit in OU, O or CN");
        }

        ensureOrderedOu(orAddress, fieldName);
    }

    private void ensureOrderedOu(ORAddress orAddress, String fieldName) {
        Set<String> presentKeys = Set.of("OU1", "OU2", "OU3", "OU4").stream()
            .filter(key -> StringUtils.hasText(orAddress.get(key)))
            .collect(Collectors.toSet());

        for (int i = 2; i <= 4; i++) {
            if (presentKeys.contains("OU" + i) && !presentKeys.contains("OU" + (i - 1))) {
                throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must not skip OU levels");
            }
        }
    }

    private String extractIcaoUnit(String address) {
        String normalizedAddress = address.trim().toUpperCase(Locale.ROOT);
        if (ICAO_8_CHAR.matcher(normalizedAddress).matches()) {
            return normalizedAddress;
        }

        ORAddress orAddress = ORAddress.parse(normalizedAddress);
        return firstIcaoUnit(orAddress)
            .orElseThrow(() -> new IllegalArgumentException("Sender O/R address does not contain an ICAO unit for certificate binding"));
    }

    private boolean containsIcaoUnit(ORAddress orAddress) {
        return firstIcaoUnit(orAddress).isPresent();
    }

    private java.util.Optional<String> firstIcaoUnit(ORAddress orAddress) {
        return java.util.stream.Stream.concat(
                orAddress.organizationalUnits().stream(),
                java.util.stream.Stream.of(orAddress.get("O"), orAddress.get("CN"))
            )
            .map(this::normalized)
            .filter(StringUtils::hasText)
            .filter(unit -> ICAO_8_CHAR.matcher(unit).matches())
            .findFirst();
    }

    private String normalized(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}
