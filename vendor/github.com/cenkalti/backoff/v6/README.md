# Exponential Backoff [![GoDoc][godoc image]][godoc]

This is a Go port of the exponential backoff algorithm from [Google's HTTP Client Library for Java][google-http-java-client].

[Exponential backoff][exponential backoff wiki]
is an algorithm that uses feedback to multiplicatively decrease the rate of some process,
in order to gradually find an acceptable rate.
The retries exponentially increase and stop increasing when a certain threshold is met.

## Usage

Import path is `github.com/cenkalti/backoff/v6`. Please note the version part at the end.

For most cases, use `Retry` function. See [example_test.go][example] for an example.

If you have specific needs, copy `Retry` function (from [retry.go][retry-src]) into your code and modify it as needed.

### Handling errors

On failure, `Retry` always returns a `*RetryError`. It carries the last operation error (`LastErr`) and the reason retrying stopped (`Cause`). Inspect it with `errors.Is`, or reach the struct with `AsRetryError`:

```go
result, err := backoff.Retry(ctx, operation)
switch {
case errors.Is(err, backoff.ErrPermanent):
	// the operation returned a Permanent error
case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
	// the caller's context was cancelled or its deadline expired
case errors.Is(err, backoff.ErrMaxElapsedTime):
	// the WithMaxElapsedTime budget was exhausted
case errors.Is(err, backoff.ErrExhausted):
	// WithMaxTries was reached or the backoff policy returned Stop
}

// The last operation error is always available, whatever the cause:
if re := backoff.AsRetryError(err); re != nil {
	log.Printf("gave up after last error: %v", re.LastErr)
}
```

Mark an error non-retriable with `backoff.Permanent(err)`; `Retry` stops immediately and returns a `*RetryError` whose `Cause` is `ErrPermanent` and whose `LastErr` is `err`.

### Bounding total time

Two independent limits cap how long `Retry` runs, and they behave differently:

- A **context deadline** (`context.WithTimeout`) is reactive: it interrupts the wait between attempts and — if your operation observes the context — can abort an in-flight attempt. `Retry` reports it as `context.DeadlineExceeded`.
- **`WithMaxElapsedTime`** bounds only retry scheduling: it is checked between attempts, never interrupts a running operation, and is reported as `ErrMaxElapsedTime`.

`WithMaxElapsedTime` defaults to 15 minutes, so **both limits are active unless you override it** — pass `backoff.WithMaxElapsedTime(0)` to rely solely on the context.

## Contributing

* I would like to keep this library as small as possible.
* Please don't send a PR without opening an issue and discussing it first.
* If proposed change is not a common use case, I will probably not accept it.

[godoc]: https://pkg.go.dev/github.com/cenkalti/backoff/v6
[godoc image]: https://godoc.org/github.com/cenkalti/backoff?status.png

[google-http-java-client]: https://github.com/google/google-http-java-client/blob/da1aa993e90285ec18579f1553339b00e19b3ab5/google-http-client/src/main/java/com/google/api/client/util/ExponentialBackOff.java
[exponential backoff wiki]: http://en.wikipedia.org/wiki/Exponential_backoff

[retry-src]: https://github.com/cenkalti/backoff/blob/v6/retry.go
[example]: https://github.com/cenkalti/backoff/blob/v6/example_test.go
