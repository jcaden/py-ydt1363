"""
YD/T 1363 Protocol Frame Definitions and Parsing
"""

from dataclasses import dataclass
from enum import Enum
import binascii
import logging
from flags import Flags
from .utils import (
    VER,
    to_ascii_hex_bytes,
    calculate_lchksum,
    calculate_chksum,
    from_ascii_hex_bytes,
    SOI,
    EOI,
)

logger = logging.getLogger(__name__)


class PackStatus(Flags):
    """
    Represents the Pack Status flags as per Table 58.
    """

    discharge_overcurrent_protection = ()
    short_circuit_protection = ()
    undervoltage_protection = ()
    undervoltage_alarm = ()
    overvoltage_protection = ()
    overvoltage_alarm = ()
    low_temperature_protection = ()
    low_temperature_alarm = ()
    high_temperature_protection = ()
    high_temperature_alarm = ()
    protection_status = ()
    alarm_status = ()
    discharge_state = ()
    charging_state = ()
    discharging_mos = ()
    charging_mos = ()


class VoltageStatus(Flags):
    """
    Represents the Voltage Status flags as per Table 58.
    """

    single_cell_overvoltage_protection = ()
    single_cell_undervoltage_protection = ()
    total_voltage_overvoltage_protection = ()
    total_voltage_undervoltage_protection = ()
    single_cell_high_voltage_alarm = ()
    single_cell_low_voltage_alarm = ()
    total_voltage_high_voltage_alarm = ()
    total_voltage_low_voltage_alarm = ()
    voltage_difference_alarm = ()
    no_longer_release_overvoltage_protection = ()
    no_longer_release_undervoltage_protection = ()
    temperature_difference_alarm = ()
    cell_failure = ()
    burnout_fuse = ()
    voltage_difference_protection = ()
    system_enters_sleep_mode = ()


class CurrentState(Flags):
    """Represents the Current State flags as per Table 58."""

    charging = ()
    discharging = ()
    charging_overcurrent_protection = ()
    short_circuit_protection = ()
    discharge_overcurrent_1_protection = ()
    discharge_overcurrent_2_protection = ()
    charging_current_alarm = ()
    discharge_current_alarm = ()
    no_longer_automatically_release = ()
    reverse_connection_protection = ()
    current_vale_multiplier_10_or_100 = ()
    start_current_limiting = ()
    battery_status13 = ()
    battery_status14 = ()
    battery_status15 = ()
    reserved = ()


class BatteryStatus(Enum):
    """Represents the Battery Status as per Table 58."""

    DISCHARGE = 0
    CHARGING = 1
    LOAD_IN_POSITION = 2
    CHARGING_IN_POSITION = 3
    NO_LOAD = 4


class TemperatureState(Flags):
    """Represents the Temperature State flags as per Table 58."""

    charging_high_temperature_protection = ()
    charging_low_temperature_protection = ()
    discharge_high_temperature_protection = ()
    discharge_low_temperature_protection = ()
    environment_high_temperature_protection = ()
    environment_low_temperature_protection = ()
    power_high_temperature_protection = ()
    power_low_temperature_protection = ()
    charging_high_temperature_alarm = ()
    charging_low_temperature_alarm = ()
    discharge_high_temperature_alarm = ()
    discharge_low_temperature_alarm = ()
    environment_high_temperature_alarm = ()
    environment_low_temperature_alarm = ()
    power_high_temperature_alarm = ()
    power_low_temperature_alarm = ()


class FetStatus(Flags):
    """Represents the FET Status flags as per Table 58."""

    charging_mos_status = ()
    discharge_mos_status = ()
    damaged_discharge_mos = ()
    damaged_charging_mos = ()
    not_used1 = ()
    not_used2 = ()
    heating_film_on = ()
    constant_current_mos_state = ()
    turn_off_4g = ()
    charging_signal = ()
    using_pack_power = ()
    led_status_alarm = ()
    buzzer_status = ()
    afe_chif_failure = ()
    afe_alarm_pin_fault = ()
    low_battery_protection = ()


class CurrentLimit(Enum):
    """Represents the Current Limit settings as per Table 58."""

    NO_LIMIT = 0
    LIMIT_20A = 1
    LIMIT_10A = 2
    LIMIT_25A = 3


class StateMachine(Flags):
    """Represents the State Machine flags as per Table 58."""

    initialization = ()
    self_test = ()
    ready = ()
    discharge = ()
    charge = ()
    failure = ()
    power_off = ()
    tooling_mode = ()


class InputOutputStatus(Flags):
    """Represents the Input/Output Status flags as per Table 58."""

    charger_online = ()
    acc_signal = ()
    on_signal = ()
    aersol_detection = ()
    battery_discharge_lock = ()
    anti_theft_lock = ()
    battery_charging_lock = ()
    not_used8 = ()
    pre_discharging_mos = ()
    not_used10 = ()
    not_used11 = ()
    not_used12 = ()
    crystal_oscillator_failure = ()
    eep_malfunction = ()
    not_used15 = ()
    not_used16 = ()


class RealtimeDataFrame:
    """
    Represents a Realtime Data Frame within the YD/T 1363 protocol.
    Structure based on Table 57.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, data: bytes):
        """Parses the Realtime Data Frame from raw bytes."""
        # pylint: disable=too-many-statements
        self.slave_addr = data[0]
        self.current = int.from_bytes(data[1:3], "big") / 1000
        self.total_voltage = int.from_bytes(data[3:5], "big") / 100
        self.soc = int.from_bytes(data[5:7], "big")
        self.soh = int.from_bytes(data[7:9], "big")
        self.remaining_capacity = int.from_bytes(data[9:11], "big") / 100
        self.full_charge_capacity = int.from_bytes(data[11:13], "big") / 100
        self.design_capacity = int.from_bytes(data[13:15], "big") / 100
        self.number_of_cycles = int.from_bytes(data[15:17], "big")
        self.number_of_cells = data[17]
        self.cell_voltages = [
            int.from_bytes(data[18 + i * 2 : 20 + i * 2], "big") / 1000
            for i in range(self.number_of_cells)
        ]
        index = 18 + self.number_of_cells * 2
        self.cell_temperature = data[index]
        index += 1
        self.battery_temperature = [
            int.from_bytes(data[index + i * 2 : index + i * 2 + 2], "big") / 10 for i in range(4)
        ]
        index += 8
        self.mos_temperature = int.from_bytes(data[index : index + 2], "big") / 10
        index += 2
        self.env_temperature = int.from_bytes(data[index : index + 2], "big") / 10
        index += 2
        self.pack_status = PackStatus(int.from_bytes(data[index : index + 2], "big"))
        index += 2
        self.voltage_status = VoltageStatus(int.from_bytes(data[index : index + 2], "big"))
        index += 2
        # Filter bit for battery status, according to definition of current state in table 58
        self.current_state = CurrentState(int.from_bytes(data[index : index + 2], "big") & 0xAFFF)
        self.battery_status = BatteryStatus(
            (int.from_bytes(data[index : index + 2], "big") & 0x7000) >> 12
        )
        index += 2
        self.temperature_state = TemperatureState(int.from_bytes(data[index : index + 2], "big"))
        index += 2
        self.fet_status = FetStatus(int.from_bytes(data[index : index + 2], "big"))
        self.current_limit = CurrentLimit(
            (int.from_bytes(data[index : index + 2], "big") & 0x00F0) >> 4
        )
        index += 2
        self.state_machine = StateMachine(data[index])
        index += 1
        self.input_output_status = InputOutputStatus(int.from_bytes(data[index : index + 2], "big"))
        index += 2
        self.boot_version = int.from_bytes(data[index : index + 2], "big")
        index += 2
        self.software_version = int.from_bytes(data[index : index + 2], "big")
        index += 2
        self.number_of_parameters = int.from_bytes(data[index : index + 2], "big")
        index += 2
        self.maximum_cell_voltage = int.from_bytes(data[index : index + 2], "big") / 1000
        index += 2
        self.minimum_cell_voltage = int.from_bytes(data[index : index + 2], "big") / 1000
        index += 2
        self.maximum_temperature = int.from_bytes(data[index : index + 2], "big") / 10
        index += 2
        self.minimum_temperature = int.from_bytes(data[index : index + 2], "big") / 10
        index += 2
        self.charging_overcurrent_alarm = int.from_bytes(data[index : index + 2], "big") / 10
        index += 2
        self.discharging_overcurrent_alarm = int.from_bytes(data[index : index + 2], "big") / 10
        index += 2
        self.reserved = data[index:]

    def __str__(self) -> str:
        return (
            f"RealtimeDataFrame(SLAVE_ADDR={self.slave_addr:02X}, "
            f"CURRENT={self.current:.2f}A, "
            f"TOTAL_VOLTAGE={self.total_voltage:.2f}V, "
            f"SOC={self.soc}%, SOH={self.soh}%, "
            f"REMAINING_CAPACITY={self.remaining_capacity:.2f}Ah, "
            f"FULL_CHARGE_CAPACITY={self.full_charge_capacity:.2f}Ah, "
            f"DESIGN_CAPACITY={self.design_capacity:.2f}Ah, "
            f"NUMBER_OF_CYCLES={self.number_of_cycles}, "
            f"NUMBER_OF_CELLS={self.number_of_cells}, "
            f"CELL_VOLTAGES={[f'{v:.3f}V' for v in self.cell_voltages]}, "
            f"CELL_TEMPERATURE={self.cell_temperature}, "
            f"BATTERY_TEMPERATURE={[f'{t}°C' for t in self.battery_temperature]}, "
            f"MOS_TEMPERATURE={self.mos_temperature:.2f}°C, "
            f"ENV_TEMPERATURE={self.env_temperature:.2f}°C), "
            f"PACK_STATUS={self.pack_status}, "
            f"VOLTAGE_STATUS={self.voltage_status}, "
            f"CURRENT_STATE={self.current_state}, "
            f"BATTERY_STATE={self.battery_status}, "
            f"TEMPERATURE_STATE={self.temperature_state}, "
            f"FET_STATUS={self.fet_status}, "
            f"CURRENT_LIMIT={self.current_limit},"
            f"STATE_MACHINE={self.state_machine}, "
            f"INPUT_OUTPUT_STATUS={self.input_output_status}, "
            f"BOOT_VERSION={self.boot_version}, "
            f"SOFTWARE_VERSION={self.software_version}, "
            f"NUMBER_OF_PARAMETERS={self.number_of_parameters}, "
            f"MAXIMUM_CELL_VOLTAGE={self.maximum_cell_voltage:.3f}V, "
            f"MINIMUM_CELL_VOLTAGE={self.minimum_cell_voltage:.3f}V, "
            f"MAXIMUM_TEMPERATURE={self.maximum_temperature:.1f}°C, "
            f"MINIMUM_TEMPERATURE={self.minimum_temperature:.1f}°C, "
            f"CHARGING_OVERCURRENT_ALARM={self.charging_overcurrent_alarm:.1f}A, "
            f"DISCHARGING_OVERCURRENT_ALARM={self.discharging_overcurrent_alarm:.1f}A, "
            f"RESERVED={binascii.hexlify(self.reserved)}"
            ")"
        )

    def serialize(self) -> bytes:
        """
        Serializes into bytes ready to be consumed as the info field of a frame
        """
        result = bytearray()
        result.extend(self.slave_addr.to_bytes(1, "big"))
        result.extend(int(self.current * 1000).to_bytes(2, "big"))
        result.extend(int(self.total_voltage * 100).to_bytes(2, "big"))
        result.extend(self.soc.to_bytes(2, "big"))
        result.extend(self.soh.to_bytes(2, "big"))
        result.extend(int(self.remaining_capacity * 100).to_bytes(2, "big"))
        result.extend(int(self.full_charge_capacity * 100).to_bytes(2, "big"))
        result.extend(int(self.design_capacity * 100).to_bytes(2, "big"))
        result.extend(self.number_of_cycles.to_bytes(2, "big"))
        result.extend(self.number_of_cells.to_bytes(1, "big"))
        for v in self.cell_voltages:
            result.extend(int(v * 1000).to_bytes(2, "big"))
        result.extend(self.cell_temperature.to_bytes(1, "big"))
        for t in self.battery_temperature:
            result.extend(int(t * 10).to_bytes(2, "big"))
        result.extend(int(self.mos_temperature * 10).to_bytes(2, "big"))
        result.extend(int(self.env_temperature * 10).to_bytes(2, "big"))
        result.extend(int(self.pack_status).to_bytes(2, "big"))
        result.extend(int(self.voltage_status).to_bytes(2, "big"))
        current_state_val = (int(self.current_state) & 0xAFFF) | (
            (self.battery_status.value & 0x7) << 12
        )
        result.extend(current_state_val.to_bytes(2, "big"))
        result.extend(int(self.temperature_state).to_bytes(2, "big"))
        fet_status = int(self.fet_status)
        current_limit_val = (int(self.current_limit.value) & 0x0F) << 4
        result.extend(((fet_status & 0xFFF0) | current_limit_val).to_bytes(2, "big"))
        result.extend(int(self.state_machine).to_bytes(1, "big"))
        result.extend(int(self.input_output_status).to_bytes(2, "big"))
        result.extend(self.boot_version.to_bytes(2, "big"))
        result.extend(self.software_version.to_bytes(2, "big"))
        result.extend(self.number_of_parameters.to_bytes(2, "big"))
        result.extend(int(self.maximum_cell_voltage * 1000).to_bytes(2, "big"))
        result.extend(int(self.minimum_cell_voltage * 1000).to_bytes(2, "big"))
        result.extend(int(self.maximum_temperature * 10).to_bytes(2, "big"))
        result.extend(int(self.minimum_temperature * 10).to_bytes(2, "big"))
        result.extend(int(self.charging_overcurrent_alarm * 10).to_bytes(2, "big"))
        result.extend(int(self.discharging_overcurrent_alarm * 10).to_bytes(2, "big"))
        result.extend(self.reserved)

        return result


@dataclass
class InfoType:
    """
    Represents the INFO field of a Frame that can have different types depending on the frame type.
    It offers a common interface for serialization and string representation.
    """

    info = bytes | RealtimeDataFrame

    def serialize(self) -> bytes:
        """
        Serializes the info field into bytes for frame serialization.
        """
        if isinstance(self.info, bytes):
            return self.info

        if isinstance(self.info, RealtimeDataFrame):
            return self.info.serialize()

        raise TypeError(
            f"Unexpected type for info, found {type(self.info)} expected bytes or RealtimeDataFrame"
        )

    def __init__(self, info: bytes | RealtimeDataFrame):
        self.info = info

    def __str__(self) -> str:
        info = self.info.hex().upper() if isinstance(self.info, bytes) else self.info
        return f"{info}"

    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class BMSFrame:
    """
    Represents a data frame of the YD/T 1363 protocol.
    Structure based on Table 1.
    """

    adr: int
    cid1: int
    cid2: int
    info: InfoType

    def __init__(self, adr: int, cid1: int, cid2: int, info: InfoType):
        self.adr = adr
        self.cid1 = cid1
        self.cid2 = cid2

        self._parse_info(info)

    @classmethod
    def deserialize(cls, packet: bytearray):
        """
        Parses a raw packet (including SOI and EOI) and validates checksums.
        packet format: b'>20014A...' + b'\r'
        """
        # The ASCII content is between SOI (index 0) and CHKSUM (last 5 bytes: 4 chk + 1 EOI)
        # Structure: SOI (1) | BODY_ASCII (N) | CHKSUM_ASCII (4) | EOI (1)

        if len(packet) < 14:  # Approximate min length
            raise ValueError("Packet too short")

        ascii_body = packet[1:-5]
        received_chksum = packet[-5:-1]

        # 1. Validate CHKSUM
        # The checksum is calculated over the entire ASCII body
        calculated_chksum = calculate_chksum(ascii_body)

        if calculated_chksum != received_chksum:
            raise ValueError(
                f"Checksum Error: Received {received_chksum}, Calculated {calculated_chksum}"
            )

        # 2. Decode ASCII fields to integers
        # VER (2 chars), ADR (2 chars), CID1 (2 chars), CID2 (2 chars), LENGTH (4 chars)
        ver = from_ascii_hex_bytes(ascii_body[0:2])
        adr = from_ascii_hex_bytes(ascii_body[2:4])
        cid1 = from_ascii_hex_bytes(ascii_body[4:6])
        cid2 = from_ascii_hex_bytes(ascii_body[6:8])
        length_field = from_ascii_hex_bytes(ascii_body[8:12])

        if ver != VER:
            raise ValueError(f"Unsupported VER: {ver:02X}")

        # 3. Validate LENGTH and LCHKSUM
        lchksum_rec = (length_field & 0xF000) >> 12
        lenid = length_field & 0x0FFF

        lchksum_calc = calculate_lchksum(lenid)
        if lchksum_rec != lchksum_calc:
            logger.debug("LCHKSUM Error: Received %i, Calculated %i", lchksum_rec, lchksum_calc)
            raise ValueError("LCHKSUM Error")

        # 4. Extract INFO
        # INFO is in ASCII hex after byte 12 of the body.
        # Its length in REAL BYTES is lenid. Its ASCII length is lenid * 2.
        info_ascii_segment = ascii_body[12:]

        if len(info_ascii_segment) != lenid:
            raise ValueError(
                f"INFO length mismatch. Expected {lenid}, received {len(info_ascii_segment)}"
            )

        return BMSFrame(
            adr=adr,
            cid1=cid1,
            cid2=cid2,
            info=InfoType(bytes.fromhex(info_ascii_segment.decode("ascii"))),
        )

    def _parse_info(self, info: InfoType):
        """Parses the INFO field and changes info into the specific type."""
        if self.cid2 == 0x85:
            self.info = info
            if isinstance(info.info, bytes):
                info.info = RealtimeDataFrame(info.info)
            else:
                if not isinstance(info.info, RealtimeDataFrame):
                    raise TypeError(
                        f"Unexpected type for info, found {type(info.info)} expected bytes of RealtimeDataFrame"
                    )
        else:
            self.info = info

    def __str__(self) -> str:
        return f"BMSFrame(ADR={self.adr:02X}, CID1={self.cid1:02X}, CID2={self.cid2:02X}, INFO={self.info}"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self) -> bytes:
        """Converts the object into bytes ready for transmission (wire format)."""

        # 1. Prepare "raw" content (before ASCII hex conversion)
        # LENGTH construction as per Table 4
        info_bytes = self.info if isinstance(self.info, bytes) else self.info.serialize()
        lenid = len(info_bytes) * 2  # Length in bytes of INFO (raw)
        lchksum = calculate_lchksum(lenid)

        # Build the LENGTH field (2 raw bytes combined)
        # Table 4: D15-D12 is LCHKSUM, D11-D0 is LENID
        length_val = (lchksum << 12) | (lenid & 0xFFF)

        # 2. Convert fields to ASCII Hex stream
        # Note: SOI and EOI are NOT converted to ASCII hex, they remain raw

        payload_ascii = b""
        payload_ascii += to_ascii_hex_bytes(VER, 1)
        payload_ascii += to_ascii_hex_bytes(self.adr, 1)
        payload_ascii += to_ascii_hex_bytes(self.cid1, 1)
        payload_ascii += to_ascii_hex_bytes(self.cid2, 1)
        payload_ascii += to_ascii_hex_bytes(length_val, 2)  # LENGTH is 2 raw bytes -> 4 ascii chars

        # INFO should already be raw bytes here, we convert to ASCII Hex
        # If info is b'\x01', it becomes b'01'
        info_ascii = b"".join(to_ascii_hex_bytes(b, 1) for b in info_bytes)
        # info_ascii = info_bytes
        payload_ascii += info_ascii

        # 3. Calculate CHKSUM over the entire ASCII stream (except SOI, EOI, CHKSUM)
        chksum_ascii = calculate_chksum(payload_ascii)

        # 4. Assemble final frame
        return bytes([SOI]) + payload_ascii + chksum_ascii + bytes([EOI])
