# =============================================================================
# RIG Security Scanner — Makefile
# =============================================================================
# Targets:
#   build       — Build the Docker image
#   scan        — Run a scan:  make scan target=example.com
#   scan-full   — Full scan with all modules
#   scan-quick  — Quick scan (recon only)
#   shell       — Open a bash shell inside the container
#   config      — Show effective configuration
# =============================================================================

.DEFAULT_GOAL := help

TARGET ?= example.com
CONFIG ?=

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the Docker image (docker compose build)
	docker compose build rig-scanner

.PHONY: scan
scan: ## Run a scan: make scan target=example.com
	$(eval SCAN_ARGS := scan $(TARGET))
	$(if $(CONFIG), $(eval SCAN_ARGS := $(SCAN_ARGS) -c /app/config/$(notdir $(CONFIG))))
	RIG_NETWORK_MODE=$(RIG_NETWORK_MODE) \
	docker compose run --rm rig-scanner $(SCAN_ARGS)

.PHONY: scan-full
scan-full: ## Full scan with all modules: make scan-full target=example.com
	TARGET=$(TARGET) docker compose run --rm full-scan

.PHONY: scan-quick
scan-quick: ## Quick scan (recon only): make scan-quick target=example.com
	TARGET=$(TARGET) docker compose run --rm quick-scan

.PHONY: shell
shell: ## Open a bash shell inside the container
	docker compose run --rm rig-scanner bash

.PHONY: config
config: ## Show effective configuration (from defaults + any found YAML)
	python -c "from src.config import load_config; import json; print(json.dumps(load_config(), indent=2, default=str))"

.PHONY: clean
clean: ## Remove cached Python files and pytest artifacts
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache .coverage
