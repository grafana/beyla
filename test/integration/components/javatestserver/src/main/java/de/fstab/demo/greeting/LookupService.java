package de.fstab.demo.greeting;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.concurrent.CompletableFuture;

@Service
public class LookupService {
    private static final Logger logger = LoggerFactory.getLogger(LookupService.class);

    private final RestTemplate restTemplate;

    public LookupService(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    @Async
    public CompletableFuture<String> callAsync() throws InterruptedException {
        logger.info("Making async call");
        String results = restTemplate.getForObject("http://ntestserver:3030/traceme", String.class);
        return CompletableFuture.completedFuture(results);
    }

}