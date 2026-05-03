package it.technosky.server.p3.x400;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.address.ORAddress;

@Component
public class X400AddressBuilder {

    public String buildPresentationAddress(String protocolIndex, String protocolAddress, String serverAddress) {
        return String.format("%s/%s=%s", normalize(protocolIndex), normalize(protocolAddress), normalize(serverAddress));
    }

    public String buildOrAddress(
        String commonName,
        String organizationUnit,
        String organizationName,
        String privateManagementDomain,
        String administrationManagementDomain,
        String countryName,
        String... additionalOrganizationUnits
    ) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("C", normalize(countryName).toUpperCase(Locale.ROOT));
        attributes.put("ADMD", normalize(administrationManagementDomain).toUpperCase(Locale.ROOT));
        attributes.put("PRMD", normalize(privateManagementDomain).toUpperCase(Locale.ROOT));
        attributes.put("O", normalize(organizationName).toUpperCase(Locale.ROOT));
        attributes.put("OU1", normalize(organizationUnit).toUpperCase(Locale.ROOT));

        if (additionalOrganizationUnits != null) {
            for (int i = 0; i < additionalOrganizationUnits.length && i < 3; i++) {
                String value = normalize(additionalOrganizationUnits[i]).toUpperCase(Locale.ROOT);
                if (StringUtils.hasText(value)) {
                    attributes.put("OU" + (i + 2), value);
                }
            }
        }

        if (StringUtils.hasText(commonName) && !"\"\"".equals(commonName.trim())) {
            attributes.put("CN", commonName.trim());
        }

        return ORAddress.of(attributes).toCanonicalString();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
