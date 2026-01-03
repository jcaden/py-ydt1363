"""
Protocol parsing and packet generation
"""

import logging
from typing import List
from .utils import SOI, EOI
from .frame import BMSFrame, InfoType

logger = logging.getLogger(__name__)


class BMSProtocol:
    """
    Handles parsing and building of YDT1363 protocol packets.
    """

    def __init__(self):
        self._buffer = bytearray()

    def feed_data(self, data: bytes) -> List[BMSFrame]:
        """
        Feeds raw data received from transport (serial/socket).
        Returns a list of decoded BMSFrames if packets are completed.
        """
        self._buffer.extend(data)
        frames: List[BMSFrame] = []

        while True:
            # Look for SOI
            start_idx = self._buffer.find(SOI)

            # Move buffer to the start of SOI
            if start_idx > 0:
                del self._buffer[:start_idx]
            elif start_idx < 0:
                # empty buffer, nothing to return
                self._buffer = bytearray()
                return frames

            # Look for EOI
            end_idx = self._buffer.find(EOI)
            if end_idx < 0:
                # Incomplete packet, wait for more data
                return frames

            # We have a potential packet between start_idx (0) and end_idx
            raw_packet = self._buffer[: end_idx + 1]

            try:
                frame = BMSFrame.deserialize(raw_packet)
                if frame:
                    frames.append(frame)
                # Remove processed packet from buffer
                del self._buffer[: end_idx + 1]
            except ValueError as e:
                # Checksum failed or invalid format.
                # Discard only the SOI and try to find another SOI inside.
                logger.error("Error parsing packet: %s", str(e))
                del self._buffer[0]
                continue

    def build_frame(self, adr: int, cid1: int, cid2: int, info: InfoType) -> bytes:
        """Helper to quickly create output bytes."""
        frame = BMSFrame(adr=adr, cid1=cid1, cid2=cid2, info=info)
        return frame.serialize()
