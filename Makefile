
test:
	uv run pytest -v

test-coverage:
	uv run pytest -v --cov=secureai --cov-report=term-missing  --cov-fail-under=95

format:
	uv run ruff format

check-format:
	uv run ruff format --check

lint:
	uv run ruff check --fix

check-lint:
	uv run ruff check

qa-all-fix: format lint

qa-all: check-format check-lint

.PHONY: test test-coverage format check-format lint check-lint qa-all-fix qa-all
