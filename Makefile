# Supported Python versions
PYTHON_VERSIONS = 3.10 3.11 3.12 3.13 3.14 3.15
DEFAULT_PYTHON = 3.10

# Install dependencies
.PHONY: install
install:
	@uv sync
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Install dev dependencies
.PHONY: install-dev
install-dev:
	@uv sync --extra dev
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Update dependencies
.PHONY: lock
lock:
	@uv lock
	@uv lock --directory tools/semgrep
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


# Upgrade dependencies
.PHONY: upgrade
upgrade:
	@uv lock --upgrade
	@uv lock --directory tools/semgrep --upgrade
	@uv sync --all-extras
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Start example-app
.PHONY: start-example
start-example:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose up --build fastapi-guard-example
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

.PHONY: run-example
run-example:
	@COMPOSE_BAKE=true docker compose build fastapi-guard-example
	@docker compose up fastapi-guard-example
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Stop
.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Restart
.PHONY: restart
restart: stop start-example

# Lint code
.PHONY: lint
lint:
	@COMPOSE_BAKE=true docker compose run --rm --no-deps fastapi-guard sh -c "echo 'Formatting w/ Ruff...' && echo '' && ruff format --check . && echo '' && echo '' && echo 'Linting w/ Ruff...' && echo '' && ruff check . && echo '' && echo '' && echo 'Type checking w/ Mypy...' && echo '' && mypy . && echo '' && echo '' && echo 'Finding dead code w/ Vulture...' && echo '' && vulture"
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Fix code
.PHONY: fix
fix:
	@echo "Fixing formatting w/ Ruff..."
	@echo ''
	@uv run ruff check --fix .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Find dead code with Vulture
.PHONY: vulture
vulture:
	@echo "Finding dead code with Vulture..."
	@echo ''
	@uv run vulture
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Security scan with Bandit
.PHONY: bandit
bandit:
	@echo "Running Bandit security scan..."
	@echo ''
	@uv run bandit -r guard -ll
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Check dependencies with Safety
.PHONY: safety
safety:
	@echo "Checking dependencies with Safety..."
	@echo ''
	@uv run safety scan
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Audit dependencies with pip-audit
.PHONY: pip-audit
pip-audit:
	@echo "Auditing dependencies with pip-audit..."
	@echo ''
	@uv run pip-audit
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Analyze code complexity with Radon
.PHONY: radon
radon:
	@echo "Analyzing code complexity with Radon..."
	@echo ''
	@echo "Cyclomatic Complexity:"
	@uv run radon cc guard -nc
	@echo ''
	@echo "Maintainability Index:"
	@uv run radon mi guard -nc
	@echo ''
	@echo "Raw Metrics:"
	@uv run radon raw guard
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Check complexity thresholds with Xenon
.PHONY: xenon
xenon:
	@echo "Checking complexity thresholds with Xenon..."
	@echo ''
	@uv run xenon guard --max-absolute B --max-modules A --max-average A
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Analyze dependencies with Deptry
.PHONY: deptry
deptry:
	@echo "Analyzing dependencies with Deptry..."
	@echo ''
	@uv run deptry .
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Static analysis with Semgrep
.PHONY: semgrep
semgrep:
	@echo "Running Semgrep static analysis..."
	@echo ''
	@uv run --project tools/semgrep --locked semgrep --config=auto guard
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Run all security checks
.PHONY: security
security: bandit safety pip-audit
	@echo "All security checks completed."

# Run all code quality checks
.PHONY: quality
quality: lint vulture radon xenon
	@echo "All code quality checks completed."

# Run all analysis tools
.PHONY: analysis
analysis: deptry semgrep
	@echo "All analysis tools completed."

# Run all checks (linting, security, quality, and analysis)
.PHONY: check-all
check-all: lint security quality analysis
	@echo "All checks completed."

# Local test
.PHONY: local-test
local-test:
	@REDIS_URL=$${REDIS_URL:-redis://localhost:6379} \
	uv run pytest -v --cov=guard --cov-report=term-missing
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Run tests (default Python version)
.PHONY: test
test:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Run All Python versions
.PHONY: test-all
test-all: test-3.10 test-3.11 test-3.12 test-3.13 test-3.14 test-3.15

# Python 3.10
.PHONY: test-3.10
test-3.10:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.10 docker compose build fastapi-guard
	@PYTHON_VERSION=3.10 docker compose run --rm fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.11
.PHONY: test-3.11
test-3.11:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.11 docker compose build fastapi-guard
	@PYTHON_VERSION=3.11 docker compose run --rm fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.12
.PHONY: test-3.12
test-3.12:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.12 docker compose build fastapi-guard
	@PYTHON_VERSION=3.12 docker compose run --rm fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.13
.PHONY: test-3.13
test-3.13:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.13 docker compose build fastapi-guard
	@PYTHON_VERSION=3.13 docker compose run --rm fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.14
.PHONY: test-3.14
test-3.14:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.14 docker compose build fastapi-guard
	@PYTHON_VERSION=3.14 docker compose run --rm fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.15
.PHONY: test-3.15
test-3.15:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.15 docker compose build fastapi-guard
	@PYTHON_VERSION=3.15 docker compose run --rm fastapi-guard pytest -v --cov=guard --cov-branch
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Stress Test
.PHONY: stress-test
stress-test:
	@COMPOSE_BAKE=true docker compose up --build -d fastapi-guard-example redis
	@echo "Waiting for services to start up..."
	@sleep 5
	@docker compose run --rm fastapi-guard-example uv run python examples/testing/stress_test.py --url http://fastapi-guard-example:8000 --duration 120 --concurrency 50 --ramp-up 10 --delay 0.02 --test-type standard -v
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# High-load stress test
.PHONY: high-load-stress-test
high-load-stress-test:
	@COMPOSE_BAKE=true docker compose up --build -d fastapi-guard-example redis
	@echo "Waiting for services to start up..."
	@sleep 5
	@docker compose run --rm fastapi-guard-example uv run python examples/testing/stress_test.py --url http://fastapi-guard-example:8000 --duration 180 --concurrency 100 --ramp-up 15 --delay 0.01 --test-type high_load -v
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Live smoke test
.PHONY: live-smoke
live-smoke:
	@mkdir -p tests/live_smoke/stack/wheels && find tests/live_smoke/stack/wheels -name 'fastapi_guard-*.whl' -delete
	@uv build --wheel --out-dir tests/live_smoke/stack/wheels
	@uv run python tests/live_smoke/copy_example_app.py
	@uv run python tests/live_smoke/patch_example_config.py
	@LIVE_SMOKE=1 uv run pytest tests/live_smoke -m live_smoke -v; \
	STATUS=$$?; \
	(cd tests/live_smoke/stack && docker compose -p fastapi-guard-live-smoke down -v --remove-orphans) >/dev/null 2>&1; \
	exit $$STATUS

# Serve docs
.PHONY: serve-docs
serve-docs:
	@UV_PROJECT_ENVIRONMENT=.venv/docs uv run --python 3.14 --extra dev --group docs mkdocs serve
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Lint documentation
.PHONY: lint-docs
lint-docs:
	@uv run --group docs pymarkdownlnt scan -r --respect-gitignore .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Fix documentation
.PHONY: fix-docs
fix-docs:
	@uv run --group docs pymarkdownlnt fix -r --respect-gitignore .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Prune
.PHONY: prune
prune:
	@docker system prune -f

# Clean Cache Files
.PHONY: clean
clean:
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Version Management
.PHONY: bump-version
bump-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	@uv run python .github/scripts/bump_version.py $(VERSION)

# Help
.PHONY: help
help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help

# Python versions list
.PHONY: show-python-versions
show-python-versions:
	@echo "Supported Python versions: $(PYTHON_VERSIONS)"
	@echo "Default Python version: $(DEFAULT_PYTHON)"
