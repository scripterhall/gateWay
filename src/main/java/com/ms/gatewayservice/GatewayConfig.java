package com.ms.gatewayservice;

import java.time.Duration;

import java.util.Arrays;

import java.util.Date;

import java.util.Random;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.WebSession;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Configuration
public class GatewayConfig {

   
    private WebSession webSession;
    @Value("${jwt.secret}")
    private String secret;

    @Bean
    public GlobalFilter authFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();
            ServerHttpResponse response = exchange.getResponse();
            String[] uri = request.getURI().getPath().split("/");


            // xcsrf cookie random sec string
            if (!Arrays.asList(uri).contains("init") && uri[1].equals("auth")) {
                String csrf = request.getHeaders().get("X-Csrftoken").get(0);
                
                if (this.webSession != null) {
                    String nameMethode = request.getMethod().name();
                    if (nameMethode.equals("POST") || nameMethode.equals("PUT") || nameMethode.equals("DELETE")) {
                        boolean validCsrf = csrf.equals(this.webSession.getAttribute("X-Csrftoken").toString());
                        
                        if (!validCsrf) {
                            String newCsrf = generateCsrfToken();
                            response.getHeaders().add("X-Csrftoken", newCsrf);
                            response.getHeaders().add("Access-Control-Expose-Headers", "X-Csrftoken");
                            this.webSession.getAttributes().put("X-Csrftoken", newCsrf);
                            response.setStatusCode(HttpStatus.FORBIDDEN);
                            return response.setComplete();
                        }

                    }
                   
                }
            }





            //session 
            if (Arrays.asList(uri).contains("init")) {
                return exchange.getSession()
                        .flatMap(session -> {
                            String headerCsrf = generateCsrfToken();
                            response.getHeaders().add("X-Csrftoken", headerCsrf);
                            response.getHeaders().add("Access-Control-Expose-Headers", "X-Csrftoken");
                            this.webSession = session;
                            this.webSession.getAttributes().put("X-Csrftoken", headerCsrf);
                            ResponseCookie cookie = ResponseCookie.from("SESSION", session.getId())
                                    .path("/")
                                    .maxAge(Duration.ofDays(1))
                                    .build();
                            response.getHeaders().add(HttpHeaders.SET_COOKIE, cookie.toString());
                            return chain.filter(exchange);
                        });

            }


            
            if (uri[1].equals("inscription") || Arrays.asList(uri).contains("role"))
                return chain.filter(exchange);
            if(!uri[1].equals("auth")){
            String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
            boolean valid = this.validateToken(authorizationHeader);
            if (authorizationHeader == null || authorizationHeader.isEmpty() || !valid) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            } else {
                Claims claims = this.extractToken(authorizationHeader);
                if (claims.get("roles").getClass() == String.class) {
                    // chef-projet privilege
                    switch (uri[1]) {
                        case "ticket-taches":
                            if (request.getMethod().name().equals("POST") || request.getMethod().name().equals("PUT")) {
                                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                return response.setComplete();
                            }
                            break;
                        case "sprints":
                            if (request.getMethod().name().equals("POST") || request.getMethod().name().equals("PUT")) {
                                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                return response.setComplete();
                            }
                            break;
                        case "dossiers":
                            if (request.getMethod().name().equals("POST")) {
                                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                return response.setComplete();
                            }
                            break;
                        case "sprint-backlogs":
                            if (request.getMethod().name().equals("POST") || request.getMethod().name().equals("PUT")) {
                                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                return response.setComplete();
                            }
                            break;
                        case "product-backlogs":
                            if (request.getMethod().name().equals("POST") || request.getMethod().name().equals("PUT")) {
                                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                return response.setComplete();
                            }
                            break;
                        case "histoireTickets":
                            if (request.getMethod().name().equals("POST") || request.getMethod().name().equals("PUT")) {
                                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                return response.setComplete();
                            }
                            break;
                        default:
                            break;
                    }

                }
                return chain.filter(exchange);
            }}
            return chain.filter(exchange);
        };
    }

    private String generateCsrfToken() {
        String[] hexaCaracter = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "a",
                "b", "c", "d", "e", "f" };
        String csrfString = "";
        for (int i = 0; i < 32; i++) {
            Random random = new Random();
            int randomIndex = random.nextInt(hexaCaracter.length);
            csrfString += hexaCaracter[randomIndex];
        }
        return csrfString;
    }

    private boolean validateToken(String jwtToken) {
        try {
            Claims claims = extractToken(jwtToken);
            Date expirationDate = claims.getExpiration();
            Date currentDate = new Date();
            if (currentDate.after(expirationDate)) {
                return false;
            }
            return true;
        } catch (Exception e) {
            e.getStackTrace();
            return false;
        }
    }

    private Claims extractToken(String jwtToken) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }
}
