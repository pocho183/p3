package it.technosky.server.p3;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.sql.init.SqlInitializationAutoConfiguration;
import org.springframework.context.annotation.Bean;

import it.technosky.server.p3.network.P3GatewayServer;
import it.technosky.server.p3.security.TLSContextFactory;

@SpringBootApplication(exclude = { DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, SqlInitializationAutoConfiguration.class })
public class P3 {
	
	@Value("${tls.keystore.path}")
    private String keystorePath;
    @Value("${tls.keystore.password}")
    private String keystorePassword;
    @Value("${tls.truststore.path:}")
    private String truststorePath;
    @Value("${tls.truststore.password:}")
    private String truststorePassword;
    @Value("${tls.pkix.revocation-enabled:false}")
    private boolean tlsRevocationEnabled;
    @Value("${tls.pkix.required-policy-oids:}")
    private String tlsRequiredPolicyOids;
	
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(P3.class);
		app.setBanner((environment, sourceClass, out) -> { out.println("*** SERVER P3 ***"); });
        app.setWebApplicationType(WebApplicationType.NONE);
        app.run(args);
	}
	
	@Bean
	@ConditionalOnProperty(name = "tls.enabled", havingValue = "true")
    public SSLContext sslContext(TLSContextFactory factory) {
        try {
            return factory.create(keystorePath, keystorePassword, truststorePath, truststorePassword, false, null/*, tlsRevocationEnabled, parsePolicyOids(tlsRequiredPolicyOids)
            */);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSLContext", e);
        }
    }
	
	/*
	private java.util.Set<String> parsePolicyOids(String csv) {
        if (csv == null || csv.isBlank()) {
            return java.util.Set.of();
        }
        return java.util.Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .collect(java.util.stream.Collectors.toSet());
    }*/
	
	@Bean
    public CommandLineRunner startServer(ObjectProvider<P3GatewayServer> p3GatewayServerProvider) {
        return args -> {
            P3GatewayServer p3GatewayServer = p3GatewayServerProvider.getIfAvailable();
            if (p3GatewayServer != null) {
                new Thread(() -> {
                    try {
                        p3GatewayServer.start();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            }
        };
	}

}
