package it.technosky.server.p3;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.annotation.Bean;

import it.technosky.server.p3.network.P3GatewayServer;


public class P3 {
	
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(P3.class);
		app.setBanner((environment, sourceClass, out) -> { out.println("*** SERVER P3 ***"); });
        app.setWebApplicationType(WebApplicationType.NONE);
        app.run(args);
	}
	
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
