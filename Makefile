
test:
	uv run pytest -v

format:
	uv run ruff format

check-format:
	uv run ruff format --check

lint:
	uv run ruff check --fix

check-lint:
	uv run ruff check

format-import-order:
	uv run ruff check --select I --fix

check-import-order:
	uv run ruff check --select I

qa-all-fix: format lint format-import-order

qa-all: check-format check-lint check-import-order

.PHONY: test format check-format lint check-lint format-import-order check-import-order qa-all-fix qa-all
