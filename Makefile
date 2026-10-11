.PHONY: api web dev test

# API on :8787 (scans run in-process; results under ~/.sureshot/scans)
api:
	uv run sureshot-api

# Web UI on :5173, proxying /api to the API
web:
	cd frontend && npm run dev

# Both, in one terminal
dev:
	$(MAKE) -j2 api web

test:
	uv run pytest -q
