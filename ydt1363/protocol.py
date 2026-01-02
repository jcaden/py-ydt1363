from typing import List
from .utils import SOI, EOI, from_ascii_hex_bytes, calculate_chksum, calculate_lchksum
from .frame import BMSFrame, InfoType
import logging
logger = logging.getLogger(__name__)

VER = 0x22

class BMSProtocol:
    def __init__(self):
        self._buffer = bytearray()
        
    def feed_data(self, data: bytes) -> List[BMSFrame]:
        """
        Feeds raw data received from transport (serial/socket).
        Returns a list of decoded BMSFrames if packets are completed.
        """
        self._buffer.extend(data)
        frames = []
        
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
            raw_packet = self._buffer[:end_idx+1]
            
            try:
                frame = self._parse_packet(raw_packet)
                if frame:
                    frames.append(frame)
                # Remove processed packet from buffer
                del self._buffer[:end_idx+1]
            except ValueError as e:
                # Checksum failed or invalid format.
                # Discard only the SOI and try to find another SOI inside.
                logger.error(f"Error parsing packet: {e}")
                del self._buffer[0]
                continue

    def _parse_packet(self, packet: bytearray) -> BMSFrame:
        """
        Parses a raw packet (including SOI and EOI) and validates checksums.
        packet format: b'~20014A...' + b'\r'
        """
        # The ASCII content is between SOI (index 0) and CHKSUM (last 5 bytes: 4 chk + 1 EOI)
        # Structure: SOI (1) | BODY_ASCII (N) | CHKSUM_ASCII (4) | EOI (1)
        
        if len(packet) < 14: # Approximate min length
            raise ValueError("Packet too short")
            
        ascii_body = packet[1:-5]
        received_chksum = packet[-5:-1]
        
        # 1. Validate CHKSUM
        # The checksum is calculated over the entire ASCII body
        calculated_chksum = calculate_chksum(ascii_body)
        
        if calculated_chksum != received_chksum:
            raise ValueError(f"Checksum Error: Received {received_chksum}, Calculated {calculated_chksum}")
            
        # 2. Decode ASCII fields to integers
        # VER (2 chars), ADR (2 chars), CID1 (2 chars), CID2 (2 chars), LENGTH (4 chars)
        try:
            ver = from_ascii_hex_bytes(ascii_body[0:2])
            adr = from_ascii_hex_bytes(ascii_body[2:4])
            cid1 = from_ascii_hex_bytes(ascii_body[4:6])
            cid2 = from_ascii_hex_bytes(ascii_body[6:8])
            length_field = from_ascii_hex_bytes(ascii_body[8:12])
        except ValueError:
            raise ValueError("Hex Decoding Error")

        # 3. Validate LENGTH and LCHKSUM 
        lchksum_rec = (length_field & 0xF000) >> 12
        lenid = length_field & 0x0FFF
        
        lchksum_calc = calculate_lchksum(lenid)
        if lchksum_rec != lchksum_calc:
             logger.debug(f"LCHKSUM Error: Received {lchksum_rec}, Calculated {lchksum_calc}")
             raise ValueError("LCHKSUM Error")
             
        # 4. Extract INFO
        # INFO is in ASCII hex after byte 12 of the body.
        # Its length in REAL BYTES is lenid. Its ASCII length is lenid * 2.
        info_ascii_segment = ascii_body[12:]
        
        if len(info_ascii_segment) != lenid :
            raise ValueError(f"INFO length mismatch. Expected {lenid}, received {len(info_ascii_segment)}")
            
        return BMSFrame(
            ver=ver,
            adr=adr,
            cid1=cid1,
            cid2=cid2,
            info=InfoType(bytes.fromhex(info_ascii_segment.decode('ascii')))
        )

    def build_frame(self, adr: int, cid1: int, cid2: int, info: InfoType) -> bytes:
        """Helper to quickly create output bytes."""
        frame = BMSFrame(ver=VER, adr=adr, cid1=cid1, cid2=cid2, info=info)
        return frame.serialize()
