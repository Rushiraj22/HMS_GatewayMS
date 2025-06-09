package com.hms.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class TokenFilter extends AbstractGatewayFilterFactory<TokenFilter.Config> {

    private static final String SECRET_KEY="d8d8d23488aa9080de43d829b6b6a548cdcb288c53a023cd33ca4464cb89e9302b946f60f6b1132bc100e3a51f8bdf5b79be3c350b82dea52bb6a96279a2e8d9";
    public TokenFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Implement your token validation logic here

            String path= exchange.getRequest().getPath().toString();
            if (path.contains("/user/login") || path.contains("/user/register")) {

                return chain.filter(exchange.mutate().request(r->r.header("X-Secrer-Key","SECRET")).build()); // Skip token validation for login and register paths
            }
            HttpHeaders header = exchange.getRequest().getHeaders();
            if (!header.containsKey(HttpHeaders.AUTHORIZATION) ) {
                throw new RuntimeException("Authorization header is missing");
            }
            String authHeader= header.getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new RuntimeException("Invalid Authorization header format");
            }
            String token = authHeader.substring(7);// Remove "Bearer " prefix
             try{
                 Claims claims = (Claims) Jwts.parser()
                         .setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();

                 exchange=exchange.mutate().request(r->r.header("X-Secret-Key", "SECRET")).build();

             }
                catch (Exception e) {
                    throw new RuntimeException("Invalid token");
                }

            return chain.filter(exchange);

        };
    }

    private boolean isValidToken(String token) {
        // Placeholder for actual token validation logic
        return true; // Replace with actual validation logic
    }

    public static class Config {
        // Configuration properties can be added here if needed
    }
}
