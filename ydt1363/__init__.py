"""
ydt1363: Python implementation for YDT 1363 protocol.

This library provides functionality to work with the YDT 1363 protocol.
"""

__version__ = "0.1.1"
__author__ = "José Antonio Santos Cadenas"
__all__ = ["BMSProtocol", "BMSFrame"]

from .protocol import BMSProtocol
from .frame import BMSFrame
