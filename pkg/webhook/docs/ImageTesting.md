To build and test the injector image, first build it with:

```sh
docker build -t injector -f Dockerfile .
```

Then you can see what it does by running the image on a local folder:

```sh
mkdir temp
docker run -e SDK_PKG_VERSION=v0.0.4 -e MOUNT_PATH=/var/lib/beyla/instrumentation --rm \
  -v $(pwd)/temp:/var/lib/beyla/instrumentation \
  injector
```