package de.fstab.demo.greeting;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;

@RestController
public class GreetingController {
	private final LookupService lookupService;

	public GreetingController(LookupService lookupService) {
		this.lookupService = lookupService;
	}

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
		return ResponseEntity.status(response).body("Hello, World!");
	}

	@GetMapping("/jtrace")
	public ResponseEntity<String> getDist(
			@RequestParam(required = false, defaultValue = "10", name="delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name="response") Integer response
	) throws Exception {
		randomSleep(Duration.ofMillis(delay));
		RestClient defaultClient = RestClient.create();
		String data = defaultClient.get()
				.uri("http://ntestserver:3030/traceme")
				.accept(MediaType.ALL)
				.retrieve()
				.body(String.class);
		return ResponseEntity.status(response).body(data);
	}

	@GetMapping("/jtrace2")
	public ResponseEntity<String> getDist2(
			@RequestParam(required = false, defaultValue = "10", name="delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name="response") Integer response
	) throws Exception {
		randomSleep(Duration.ofMillis(delay));
		CompletableFuture<String> aa = lookupService.callAsync();

		CompletableFuture.allOf(aa).join();
		return ResponseEntity.status(response).body(aa.get());
	}
}