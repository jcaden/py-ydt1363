# py-ydt1363

[![PyPI version](https://img.shields.io/pypi/v/ydt1363)](https://pypi.org/project/ydt1363/)
![License](https://img.shields.io/pypi/l/ydt1363)
![Python versions](https://img.shields.io/pypi/pyversions/ydt1363)

Python implementation for YDT 1363 protocol.

## Installation

### From source

```bash
pip install .
```

### Development installation

```bash
pip install -e ".[dev]"
```

## Usage

```python
import ydt1363

# Your code here
```

## Development

### Setup development environment

```bash
# Clone the repository
git clone https://github.com/jcaden/py-ydt1363.git
cd py-ydt1363

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

### Running tests

```bash
pytest
```

### Code formatting

```bash
black ydt1363 tests
```

### Linting

```bash
flake8 ydt1363 tests
mypy ydt1363
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
