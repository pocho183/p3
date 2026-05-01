package it.technosky.server.p3.security;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.Set;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class TLSContextFactory {

    private final ResourceLoader resourceLoader;

    public TLSContextFactory(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public SSLContext create(
        String keyStorePath,
        String keyStorePassword,
        String trustStorePath,
        String trustStorePassword,
        boolean revocationEnabled,
        Set<String> requiredPolicyOids
    ) {
        try {
            KeyStore keyStore = loadStore(keyStorePath, keyStorePassword, "PKCS12");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyStorePassword.toCharArray());

            TrustManagerFactory tmf = null;
            if (StringUtils.hasText(trustStorePath)) {
                KeyStore trustStore = loadStore(trustStorePath, trustStorePassword, "JKS");
                tmf = TrustManagerFactory.getInstance("PKIX");
                PKIXBuilderParameters parameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
                parameters.setRevocationEnabled(revocationEnabled);

                if (requiredPolicyOids != null && !requiredPolicyOids.isEmpty()) {
                    parameters.setExplicitPolicyRequired(true);
                    parameters.setInitialPolicies(requiredPolicyOids);
                }

                if (revocationEnabled) {
                    PKIXRevocationChecker checker = (PKIXRevocationChecker) java.security.cert.CertPathValidator.getInstance("PKIX").getRevocationChecker();
                    checker.setOptions(Set.of(PKIXRevocationChecker.Option.PREFER_CRLS));
                    parameters.addCertPathChecker(checker);
                }

                tmf.init(new CertPathTrustManagerParameters(parameters));
            }
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
            return ctx;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize TLS context", e);
        }
    }

    private KeyStore loadStore(String path, String password, String type) throws Exception {
        Resource resource = resourceLoader.getResource(path);
        try (InputStream is = resource.getInputStream()) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(is, password == null ? null : password.toCharArray());
            return keyStore;
        }
    }
}