package de.fstab.demo.greeting;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;

@RestController
public class GreetingController {
	public GreetingController() {}

	public static void randomSleep(Duration averageDuration) throws InterruptedException{
        long sleepTime;
        do {
            sleepTime = averageDuration.toMillis() + (long) (ThreadLocalRandom.current().nextGaussian() * 200);
        } while (sleepTime <= 0.0);
        Thread.sleep(sleepTime);
    }

	@GetMapping("/greeting")
	public ResponseEntity<String> getGreeting(
			@RequestParam(required = false, defaultValue = "10", name="delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name="response") Integer response
	) throws Exception {
		randomSleep(Duration.ofMillis(delay));
        java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .version(java.net.http.HttpClient.Version.HTTP_1_1)
                .build();
		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create("https://example.com"))
				.GET()
				.build();

		CompletableFuture<HttpResponse<String>> future =
				client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

		future.thenAccept(res -> {
			System.out.println("Status code: " + res.statusCode());
			//System.out.println("Body: " + res.body());
		}).join(); // Wait for completion
		return ResponseEntity.status(response).body("Hello, World!");
	}

}