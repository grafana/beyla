package de.fstab.demo.greeting;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;

@RestController
public class GreetingController {
	public GreetingController() {
	}

	public static void randomSleep(Duration averageDuration) throws InterruptedException{
        long sleepTime;
        do {
            sleepTime = averageDuration.toMillis() + (long) (ThreadLocalRandom.current().nextGaussian() * 200);
        } while (sleepTime <= 0.0);
        Thread.sleep(sleepTime);
    }

	@GetMapping("/greeting")
	public ResponseEntity<String> getDistB(
			@RequestParam(required = false, defaultValue = "10", name="delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name="response") Integer response
	) throws Exception {
		randomSleep(Duration.ofMillis(delay));
		String data = "Hello World!";
		return ResponseEntity.status(response).body(data);
	}
}
