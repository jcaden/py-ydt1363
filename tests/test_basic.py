"""
Basic tests for the ydt1363 package.
"""

import ydt1363


def test_version():
    """Test that the package has a version."""
    assert hasattr(ydt1363, "__version__")
    assert isinstance(ydt1363.__version__, str)
    assert len(ydt1363.__version__) > 0


def test_import():
    """Test that the package can be imported."""
    assert ydt1363 is not None


def test_author():
    """Test that the package has an author."""
    assert hasattr(ydt1363, "__author__")
    assert isinstance(ydt1363.__author__, str)
