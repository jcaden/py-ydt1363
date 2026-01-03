"""Utility functions and constants for YDT1363 protocol handling."""

# Constant definitions according to Table 1 and Table 2
SOI = 0x3E  # Start of Information (>)
EOI = 0x0D  # End of Information (\r)
VER = 0x22  # Protocol version (Fixed to 2.2 for generic responses)
CID1_BMS = 0x4A  # Typical ID for LFP BMS (Lithium Iron Phosphate)


def to_ascii_hex_bytes(value: int, width: int = 1) -> bytes:
    """
    Converts an integer to its ASCII Hex representation.
    Example: 0x4B -> b'4B'
    According to section 8.1, bytes are split into two ASCII codes.
    """
    fmt = f"{{:0{width * 2}X}}"
    return fmt.format(value).encode("ascii")


def from_ascii_hex_bytes(data: bytes) -> int:
    """Converts ASCII Hex bytes to an integer. Example: b'4B' -> 0x4B"""
    return int(data, 16)


def calculate_lchksum(lenid: int) -> int:
    """
    Calculates the length checksum (LCHKSUM) according to section 8.2.
    Formula: D11D10D9D8 + D7D6D5D4 + D3D2D1D0, mod 16, inverse + 1.
    """
    # LENID is 12 bits max (0x0FFF).
    # D11-D8
    high = (lenid & 0xF00) >> 8
    # D7-D4
    mid = (lenid & 0x0F0) >> 4
    # D3-D0
    low = lenid & 0x00F

    sum_val = high + mid + low
    remainder = sum_val % 16
    checksum = (~remainder & 0x0F) + 1
    return checksum & 0x0F


def calculate_chksum(ascii_data: bytes) -> bytes:
    """
    Calculates the global CHKSUM according to section 8.3.
    Sum of ASCII values, modulo 65536, inverse + 1.
    Returns 4 ASCII Hex bytes.
    """
    total_sum = sum(ascii_data)
    remainder = total_sum % 65536
    checksum = (~remainder & 0xFFFF) + 1
    # Returns as 4 ASCII Hex bytes
    return to_ascii_hex_bytes(checksum & 0xFFFF, width=2)
