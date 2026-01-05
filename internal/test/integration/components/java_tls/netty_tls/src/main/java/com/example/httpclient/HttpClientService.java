package com.example.httpclient;

import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.HttpProtocol;

import java.time.Duration;

@Service
public class HttpClientService {

    private HttpClient httpClient = HttpClient.create()
            .secure(spec -> spec.sslContext(
                    io.netty.handler.ssl.SslContextBuilder.forClient()
                            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            ))
            .protocol(HttpProtocol.HTTP11);
    private final WebClient webClient;

    public HttpClientService() {
        this.webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024))
                .build();
    }

    /**
     * Makes a GET request to the specified URL
     */
    public String makeGetRequest(String url) {
        try {
            return webClient.get()
                    .uri(url)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();
        } catch (Exception e) {
            return "Error making request: " + e.getMessage();
        }
    }

    /**
     * Makes a POST request to the specified URL with JSON body
     */
    public String makePostRequest(String url, String jsonBody) {
        try {
            return webClient.post()
                    .uri(url)
                    .header("Content-Type", "application/json")
                    .bodyValue(jsonBody)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();
        } catch (Exception e) {
            return "Error making POST request: " + e.getMessage();
        }
    }

    /**
     * Makes an async GET request
     */
    public Mono<String> makeAsyncGetRequest(String url) {
        return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(10))
                .onErrorReturn("Error in async request");
    }
}