# List of projects to provide to the make-docs script.
PROJECTS := ebpf-autoinstrument

# Used to compile Mermaid diagrams as images until this PR is not merged: https://github.com/grafana/website/pull/9196
export MERMAID_IMAGE := minlag/mermaid-cli:10.2.4

# Use alternative image until make-docs 3.0.0 is rolled out everywhere.
export DOCS_IMAGE := grafana/docs-base:dbd975af06

# Set the DOC_VALIDATOR_IMAGE to match the one defined in CI.
export DOC_VALIDATOR_IMAGE := $(shell sed -En 's, *image: "(grafana/doc-validator.*)",\1,p' "$(shell git rev-parse --show-toplevel)/.github/workflows/doc-validator.yml")
