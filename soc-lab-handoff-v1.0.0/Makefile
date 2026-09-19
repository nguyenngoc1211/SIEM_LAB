SHELL := /bin/bash

.PHONY: init up down build logs status test validate preflight check clean manifest

init:
	@test -f .env || cp .env.example .env
	@mkdir -p runtime/suricata-logs
	@chmod 755 runtime/suricata-logs

preflight: init
	./scripts/preflight.sh

up: init
	docker compose up -d --build

build: init
	docker compose build --pull

down:
	docker compose down

logs:
	docker compose logs -f gateway suricata juice-shop

status:
	./scripts/status.sh

test:
	./scripts/test-alerts.sh

check:
	./scripts/system-check.sh

validate:
	./scripts/validate.sh

manifest:
	./scripts/generate-manifest.sh

clean:
	docker compose down --remove-orphans
	rm -f runtime/suricata-logs/*.json runtime/suricata-logs/*.log runtime/suricata-logs/*.stats
