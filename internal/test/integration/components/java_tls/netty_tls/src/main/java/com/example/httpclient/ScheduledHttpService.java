package com.example.httpclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
@ConditionalOnProperty(name = "app.scheduled.enabled", havingValue = "true", matchIfMissing = true)
public class ScheduledHttpService {

    private static final Logger logger = LoggerFactory.getLogger(ScheduledHttpService.class);
    
    @Value("${app.scheduled.target-url:https://www.google.de}")
    private String targetUrl;
    
    @Autowired
    private HttpClientService httpClientService;

    /**
     * Makes a request to the configured URL every 30 seconds
     */
    @Scheduled(fixedRateString = "${app.scheduled.interval-seconds:30}000")
    public void makePeriodicRequest() {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME);
            logger.info("Making scheduled request to {} at {}", targetUrl, timestamp);
            
            long startTime = System.currentTimeMillis();
            String response = httpClientService.makeGetRequest(targetUrl);
            long duration = System.currentTimeMillis() - startTime;
            
            // Log response summary (not full HTML to avoid log spam)
            String responseSummary = response != null && response.length() > 100 
                ? response.substring(0, 100) + "..." 
                : response;
            
            logger.info("Scheduled request completed in {}ms. Response length: {} chars. Preview: {}", 
                       duration, 
                       response != null ? response.length() : 0,
                       responseSummary != null ? responseSummary.replaceAll("\\s+", " ") : "null");
                       
        } catch (Exception e) {
            logger.error("Error during scheduled request to {}: {}", targetUrl, e.getMessage());
        }
    }

    /**
     * Makes a request every 2 minutes for additional traffic variety
     */
    @Scheduled(fixedRate = 120000) // 2 minutes
    public void makePeriodicHealthCheck() {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME);
            logger.info("Making scheduled health check request to {} at {}", targetUrl, timestamp);
            
            long startTime = System.currentTimeMillis();
            String response = httpClientService.makeGetRequest(targetUrl);
            long duration = System.currentTimeMillis() - startTime;
            
            // Just log the duration for health checks
            logger.info("Health check request completed in {}ms. Status: {}", 
                       duration, 
                       response != null && !response.isEmpty() ? "SUCCESS" : "FAILED");
                       
        } catch (Exception e) {
            logger.error("Error during health check request to {}: {}", targetUrl, e.getMessage());
        }
    }
}