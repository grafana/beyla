.ONESHELL:
.DELETE_ON_ERROR:
export SHELL     := bash
export SHELLOPTS := pipefail:errexit
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rule

include docs.mk

.PHONY: mermaid
mermaid:
	@echo "### Updating Mermaid diagrams"
	$(PODMAN) run --entrypoint /bin/sh -it --rm -v .:/docs $(MERMAID_IMAGE) -c 'find /docs -name "*.mmd" | sed s/\.mmd$// | xargs -I{} /home/mermaidcli/node_modules/.bin/mmdc -i {}.mmd -o {}.png -p /puppeteer-config.json'