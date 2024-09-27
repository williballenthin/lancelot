isort:
    uvx isort --length-sort --profile black --line-length 120 src/ scripts/ tests/

black:
    uvx black --line-length 120 src/ scripts/ tests/

ruff:
    uvx ruff check --line-length 120 src/ scripts/ tests/

mypy:
    # note the src/ is not included here since there are currently no py files there
    uvx mypy --check-untyped-defs --ignore-missing-imports scripts/ tests/

lint:
    -just isort
    -just black
    -just ruff
    -just mypy
