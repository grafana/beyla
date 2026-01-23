package com.example.httpclient;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.*;

@RestController
@RequestMapping("/api")
public class HttpClientController {

    @Autowired
    private HttpClientService httpClientService;

    @Value("${app.scheduled.enabled:true}")
    private boolean scheduledEnabled;

    @Value("${app.scheduled.target-url:https://www.google.de}")
    private String scheduledTargetUrl;

    @Value("${app.scheduled.interval-seconds:30}")
    private int scheduledIntervalSeconds;

    private ExecutorService executor = Executors.newFixedThreadPool(10);
    private ForkJoinPool forkJoinPool = new ForkJoinPool(10);

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
            "status", "UP", 
            "service", "http-client-demo",
            "timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            "scheduled_requests", Map.of(
                "enabled", scheduledEnabled,
                "target_url", scheduledTargetUrl,
                "interval_seconds", scheduledIntervalSeconds
            )
        );
    }

    /**
     * Get information about scheduled requests
     */
    @GetMapping("/scheduled-info")
    public Map<String, Object> getScheduledInfo() {
        return Map.of(
            "enabled", scheduledEnabled,
            "target_url", scheduledTargetUrl,
            "interval_seconds", scheduledIntervalSeconds,
            "description", "Automatic HTTP requests are " + (scheduledEnabled ? "enabled" : "disabled")
        );
    }

    /**
     * Trigger a GET request to an external endpoint
     * Example: GET /api/request?url=https://httpbin.org/get
     */
    @GetMapping("/request")
    public Map<String, Object> makeGetRequest(@RequestParam String url) {
        long startTime = System.currentTimeMillis();
        String response = httpClientService.makeGetRequest(url);
        long duration = System.currentTimeMillis() - startTime;
        
        return Map.of(
            "target_url", url,
            "response", response,
            "duration_ms", duration,
            "method", "GET"
        );
    }

    /**
     * Trigger a POST request to an external endpoint
     * Example: POST /api/request with body: {"url": "https://httpbin.org/post", "data": {"key": "value"}}
     */
    @PostMapping("/request")
    public Map<String, Object> makePostRequest(@RequestBody Map<String, Object> requestBody) {
        String url = (String) requestBody.get("url");
        String jsonData = requestBody.get("data").toString();
        
        long startTime = System.currentTimeMillis();
        String response = httpClientService.makePostRequest(url, jsonData);
        long duration = System.currentTimeMillis() - startTime;
        
        return Map.of(
            "target_url", url,
            "request_data", jsonData,
            "response", response,
            "duration_ms", duration,
            "method", "POST"
        );
    }

    /**
     * Trigger an async GET request
     * Example: GET /api/async-request?url=https://httpbin.org/delay/2
     */
    @GetMapping("/async-request")
    public Mono<Map<String, Object>> makeAsyncGetRequest(@RequestParam String url) {
        long startTime = System.currentTimeMillis();

        return httpClientService.makeAsyncGetRequest(url)
                .map(response -> Map.of(
                    "target_url", url,
                    "response", response,
                    "duration_ms", System.currentTimeMillis() - startTime,
                    "method", "GET_ASYNC"
                ));
    }

    /**
     * Trigger an async GET request
     * Example: GET /api/async-request-c?url=https://httpbin.org/get
     */
    @GetMapping("/async-request-c")
    public Map<String, Object> makeAsyncGetRequestCallable(@RequestParam String url) throws ExecutionException, InterruptedException {
        long startTime = System.currentTimeMillis();

        // Submit a Callable task
        Future<String> future = executor.submit(() -> {
            // Make HTTP request
            return httpClientService.makeGetRequest(url);
        });

        // Get result (blocks until complete)
        String response = future.get();

        long duration = System.currentTimeMillis() - startTime;
        
        return Map.of(
            "target_url", url,
            "response", response,
            "duration_ms", duration,
            "method", "GET"
        );    
    }

    /**
     * Trigger an async GET request using ForkJoinPool
     * Example: GET /api/async-request-fj?url=https://httpbin.org/get
     */
    @GetMapping("/async-request-fj")
    public Map<String, Object> makeAsyncGetRequestForkJoin(@RequestParam String url) throws ExecutionException, InterruptedException {
        long startTime = System.currentTimeMillis();
        // Submit a Callable task to ForkJoinPool
        Future<String> future = forkJoinPool.submit(() -> {
            // Make HTTP request
            return httpClientService.makeGetRequest(url);
        });

        // Get result (blocks until complete)
        String response = future.get();

        long duration = System.currentTimeMillis() - startTime;
        
        return Map.of(
            "target_url", url,
            "response", response,
            "duration_ms", duration,
            "method", "GET_FORKJOIN",
            "pool_type", "ForkJoinPool"
        );    
    }

    /**
     * Manually trigger a request to the scheduled target URL
     */
    @PostMapping("/trigger-scheduled")
    public Map<String, Object> triggerScheduledRequest() {
        long startTime = System.currentTimeMillis();
        String response = httpClientService.makeGetRequest(scheduledTargetUrl);
        long duration = System.currentTimeMillis() - startTime;
        
        return Map.of(
            "target_url", scheduledTargetUrl,
            "response_length", response != null ? response.length() : 0,
            "duration_ms", duration,
            "method", "GET",
            "triggered_manually", true
        );
    }
}
