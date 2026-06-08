To build and test the injector image, first build it with:

```sh
docker build -t injector -f Dockerfile .
```

Then you can see what it does by running the image on a local folder:

```sh
mkdir temp
docker run -e MOUNT_PATH=/__otel_sdk_auto_instrumentation__ --rm \
  -v $(pwd)/temp:/__otel_sdk_auto_instrumentation__ \
  injector
```