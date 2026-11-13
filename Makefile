# raycert — common tasks. `make` (or `make help`) lists them.

.DEFAULT_GOAL := help
.PHONY: help build test test-native test-keychain check fmt interop pebble demo clean

# A local Pebble binary (see scripts/pebble.sh for how to build it).
PEBBLE ?= pebble

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-14s %s\n", $$1, $$2}'

build: ## The native binary, ./raycert
	rm -f raycert
	ray build --native --release -o raycert src/main.ray

test: ## Tests on the VM
	ray test

test-native: ## The same tests as native binaries
	ray test --native

test-keychain: ## Also the keychain test (a throwaway raycert-test-* item, removed at the end)
	RAYCERT_TEST_KEYCHAIN=1 ray test the_ca_key_can_live_in_the_keychain
	RAYCERT_TEST_KEYCHAIN=1 ray test --native the_ca_key_can_live_in_the_keychain

check: ## Type-check without running
	ray check

fmt: ## Format the sources
	ray fmt -w src/*.ray tests/*.ray scripts/*.ray

interop: build ## openssl as the oracle: verify, req -verify, s_server/s_client, raylang's TLS server
	./scripts/interop.sh

pebble: build ## ACME against a local Pebble (PEBBLE=path/to/pebble), renew with a hook
	PEBBLE=$(PEBBLE) ./scripts/pebble.sh

demo: build ## A throwaway CA and leaf in ./out, inspected
	rm -rf out
	./raycert ca init --home out --type ed25519
	./raycert issue web --home out --san localhost,127.0.0.1 --type p256
	./raycert inspect out/certs/web/chain.pem
	./raycert list --home out

clean: ## Remove the binary and ./out
	rm -f raycert
	rm -rf out
