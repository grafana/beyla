# Python distribution development

## Requirements

The tests require Python 3.9 or newer, `pytest`, and `packaging`.

Check the local installation:

```sh
python3 --version
python3 -m pytest --version
```

Install the test dependencies if needed:

```sh
python3 -m pip install pytest packaging
```

## Run all tests

From this directory:

```sh
python3 -m pytest -q
```

The command runs the injector safety checks, dependency analyzer tests, service metadata detection tests, and framework launch parser tests.

The local `sitecustomize.py` may print a warning about the default gRPC export protocol when Python starts. This is expected during tests and does not indicate a failure; use the pytest result and exit code.

## Run a test file

```sh
python3 -m pytest test_beyla_metadata.py -v
python3 -m pytest test_beyla_launch.py -v
python3 -m pytest test_frameworks/test_gunicorn.py -v
python3 -m pytest test_beyla_resource.py -v
python3 -m pytest test_sitecustomize.py -v
python3 -m pytest test_deps_analyser.py -v
```

Each framework parser has a matching file under `test_frameworks`. Run all
framework parser tests with:

```sh
python3 -m pytest test_frameworks -v
```

## Run one test

Use pytest's `file::class::test` selector:

```sh
python3 -m pytest \
  test_beyla_metadata.py::TestServiceMetadata::test_generic_script_uses_application_directory \
  -v
```

## Run without pytest

The suite also uses the standard-library test runner:

```sh
python3 -m unittest discover -v
```
