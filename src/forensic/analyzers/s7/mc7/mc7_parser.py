import binascii
import struct
import datetime
import socket
from forensic.analyzers.s7.mc7.mc7_consts import CONNECTION_TYPE, BLOCK_ATTRIBUTE, BLOCK_LANGUAGE, BLOCK_TYPE, HEADER_SIZE, DATA_BLOCK_PARAMS_TYPE, PARAMETERS_TYPE
from forensic.analyzers.s7.mc7.mc7_convert import mc7_to_awl
from forensic.common.stream.stream import BinaryReader, StreamNotEnoughData, BasicType, uint16be, DataStruct, uint32, uint32be, dynamic, ascii_string, char, bytesbe, uint16, uint64, floatbe, ubyte
from typing import Dict


class TconPar(DataStruct):
    block_length = uint16be
    connection_id = uint16be
    connection_type = ubyte
    active_est = ubyte
    local_device_id = ubyte
    local_tsap_id_length = ubyte
    rem_subnet_id_length = ubyte
    rem_staddr_length = ubyte
    rem_tsap_id_length = ubyte
    next_staddr_length = ubyte
    local_tsap_id = uint16be
    rename1 = bytesbe(14)
    rename2 = bytesbe(6)
    #rem_subnet_id = 0
    rem_staddr = uint32
    rename3 = bytesbe(2)
    rem_tsap_id = uint16be
    rename4 = bytesbe(14)

class BlockHeaderMetadata(DataStruct):
    version = ubyte
    attribute = ubyte
    language = ubyte
    type = ubyte
    block_num = uint16be
    length = uint32be
    password = bytesbe(4)
    last_modified = bytesbe(6)
    last_interface_change = bytesbe(6)

class DbBlockMetadata(DataStruct):
    body_length = uint16be
    segment_length = uint16be
    local_data_length = uint16be
    data_length = uint16be
    data = dynamic
    segment = dynamic
    local_data = dynamic
    body = dynamic

class NonDbBlockMetadata(DataStruct):
    interface_length = uint16be
    segment_length = uint16be
    local_data_length = uint16be
    mc7_length = uint16be
    data = dynamic
    interface = dynamic
    segment = dynamic

class BlockFooterMetadata(DataStruct):
    author_name = ascii_string(8)
    block_family = ascii_string(8)
    block_name = ascii_string(8)
    block_version = ubyte
    check_sum = uint16

class MC7Parser(object):
    def __init__(self):
        self._aggregated_buffer = dict()

    @staticmethod
    def _to_version(data):
        return f'{str((data & 0xF0) >> 4)}.{str(data & 0x0F)}'

    @staticmethod
    def _to_str(data):
        return data.strip("\x00").strip(" ")

    @staticmethod
    def _to_ip(addr):
        return socket.inet_ntoa(struct.pack('<i', addr))

    @staticmethod
    def read_string_by_type(br: BinaryReader, basic_type: BasicType):
        length = br.read(basic_type)
        return br.read(ascii_string(length))

    @staticmethod
    def read_s7_datetime_from_bytes(date_byte):
        millis = struct.unpack(">I", date_byte[:4])[0]
        days = struct.unpack(">H", date_byte[4:][:2])[0]
        dt = datetime.datetime(1984, 1, 1) + datetime.timedelta(microseconds=millis * 1000, days=days)
        return dt

    def parse_block_header_metadata(self, br: BinaryReader):
        block_header_metadata = BlockHeaderMetadata(br)
        self._aggregated_buffer['version'] = block_header_metadata.version
        self._aggregated_buffer['attribute'] = BLOCK_ATTRIBUTE.get(block_header_metadata.attribute, 'Attribute ID %s' % hex(block_header_metadata.attribute))
        self._aggregated_buffer['language'] = BLOCK_LANGUAGE.get(block_header_metadata.language, 'Attribute ID %s' % hex(block_header_metadata.language))
        self._aggregated_buffer['type'] = BLOCK_TYPE.get(block_header_metadata.type, 'Attribute ID %s' % hex(block_header_metadata.type))
        self._aggregated_buffer['block_num'] = block_header_metadata.block_num
        self._aggregated_buffer['length'] = block_header_metadata.length
        password = block_header_metadata.password.hex()
        protection = True
        if password == '00000000':
            password = 'Empty'
            protection = False
        self._aggregated_buffer["password"] = password
        self._aggregated_buffer['Know-how protection'] = protection
        self._aggregated_buffer["last_modified"] = self.read_s7_datetime_from_bytes(block_header_metadata.last_modified)
        self._aggregated_buffer["last_interface_change"] = self.read_s7_datetime_from_bytes(block_header_metadata.last_interface_change)

    def parse_tcon_params(self, br: BinaryReader):
        tcon = TconPar(br)
        self._aggregated_buffer["db_ext_header"]["tcon_params"] = dict()
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["block_length"] = tcon.block_length
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["connection_id"] = tcon.connection_id  # valid range 0x0001 - 0x0fff
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["connection_type"] = CONNECTION_TYPE.get(tcon.connection_type, 'Attribute ID %s' % hex(tcon.connection_type))
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["active_est"] = tcon.active_est
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["local_device_id"] = tcon.local_device_id  # allowed values: 0 / 2 / 3 / 5
        self._aggregated_buffer["db_ext_header"]["tcon_params"]['local_tsap_id_length'] = tcon.local_tsap_id_length  # used length of the "local_tsap_id" parameter
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["rem_subnet_id_length"] = tcon.rem_subnet_id_length  # unused
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["rem_staddr_length"] = tcon.rem_staddr_length  # 0 (unspecified) / 4 (valid IP address)
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["rem_tsap_id_length"] = tcon.rem_tsap_id_length  # used length of the "rem_tsap_id" parameter
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["next_staddr_length"] = tcon.next_staddr_length  # Used length of the "next_staddr" parameter. This parameter is not relevant for TCP.
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["local_tsap_id"] = tcon.local_tsap_id  # local port number
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["rem_subnet_id"] = 0  # unused
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["rem_staddr"] = self._to_ip(tcon.rem_staddr)
        self._aggregated_buffer["db_ext_header"]["tcon_params"]["rem_tsap_id"] = tcon.rem_tsap_id  # remote port number

    def parse_db_block_metadata(self, br: BinaryReader):
        db_block_metadata = DbBlockMetadata(br)
        self._aggregated_buffer["body_length"] = db_block_metadata.body_length
        self._aggregated_buffer["segment_length"] = db_block_metadata.segment_length
        self._aggregated_buffer["local_data_length"] = db_block_metadata.local_data_length
        self._aggregated_buffer["data_length"] = db_block_metadata.data_length
        if self._aggregated_buffer["data_length"]:
            self._aggregated_buffer["data"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["data_length"]))).decode()
        if self._aggregated_buffer["segment_length"]:
            self._aggregated_buffer["segment"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["segment_length"]))).decode()
        if self._aggregated_buffer["local_data_length"]:
            self._aggregated_buffer["local_data"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["local_data_length"]))).decode()
        if self._aggregated_buffer["body_length"]:
            self._aggregated_buffer["body"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["body_length"]))).decode()

    def parse_non_db_block_metadata(self, br: BinaryReader):
        non_db_block_metadata = NonDbBlockMetadata(br)
        self._aggregated_buffer["interface_length"] = non_db_block_metadata.interface_length
        self._aggregated_buffer["segment_length"] = non_db_block_metadata.segment_length
        self._aggregated_buffer["local_data_length"] = non_db_block_metadata.local_data_length
        self._aggregated_buffer["mc7_length"] = non_db_block_metadata.mc7_length
        if self._aggregated_buffer["mc7_length"]:
            self._aggregated_buffer["data"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["mc7_length"]))).decode()
        if self._aggregated_buffer["interface_length"]:
            self._aggregated_buffer["interface"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["interface_length"]))).decode()
        if self._aggregated_buffer["segment_length"]:
            self._aggregated_buffer["segment"] = binascii.hexlify(br.read(bytesbe(self._aggregated_buffer["segment_length"]))).decode()

    def parse_non_db_block_segement(self):
        self._aggregated_buffer["used_block"] = []
        if self._aggregated_buffer["segment"]:
            segment_br = BinaryReader(binascii.unhexlify(self._aggregated_buffer["segment"]))
            self._aggregated_buffer["segment_num"] = segment_br.read(uint16)
            pointer = 0
            for x in range(0, self._aggregated_buffer["segment_num"]):
                seg_size = segment_br.read(uint16)

                self._aggregated_buffer[f"network_{x + 1}_raw"] = self._aggregated_buffer["data"][
                                                                  pointer * 2:(pointer + seg_size) * 2]
                self._aggregated_buffer[f"network_{x + 1}_mc7"] = mc7_to_awl(
                    self._aggregated_buffer[f"network_{x + 1}_raw"])
                if self._aggregated_buffer[f"network_{x + 1}_mc7"]:
                    self._aggregated_buffer["used_block"] += [" ".join(s.split(' ')[1:]) if s else s for s in
                                                              self._aggregated_buffer[f"network_{x + 1}_mc7"] if
                                                              any(xs in s for xs in ['UC', 'CC'])]
                pointer += seg_size

    def parse_block_footer_metadata(self, br: BinaryReader):
        block_footer_metadata = BlockFooterMetadata(br)
        self._aggregated_buffer["author_name"] = self._to_str(block_footer_metadata.author_name)
        self._aggregated_buffer["block_family"] = self._to_str(block_footer_metadata.block_family)
        self._aggregated_buffer["block_name"] = self._to_str(block_footer_metadata.block_name)
        self._aggregated_buffer["block_version"] = self._to_version(block_footer_metadata.block_version)
        self._aggregated_buffer["check_sum"] = block_footer_metadata.check_sum

        if self._aggregated_buffer['type'] == 'DB' and self._aggregated_buffer['data_length']:
            self._aggregated_buffer["db_ext_header"] = dict()
            if self._aggregated_buffer["block_name"] == "TCON_PAR":  # S7-300/400 only
                self.parse_tcon_params(BinaryReader(binascii.unhexlify(self._aggregated_buffer["data"])))

    def parse_db_block_body(self):
        data_struct = []
        actual_values = BinaryReader(binascii.unhexlify(self._aggregated_buffer["data"]))
        db_data = BinaryReader(binascii.unhexlify(self._aggregated_buffer["body"]))
        db_type = db_data.read(ubyte)
        fb_num = db_data.read(uint16)
        if db_type == 0xa:
            self._aggregated_buffer['db_type'] = 'InstanceDB'
            self._aggregated_buffer['FB_related'] = fb_num
        else:
            self._aggregated_buffer['db_type'] = 'GlobalDB'
        interface_len = db_data.read(uint16)
        value_position = db_data.read(uint16)
        start_values = BinaryReader(binascii.unhexlify(self._aggregated_buffer["body"])[interface_len + 7:])
        try:
            while db_data.tell() <= (interface_len + 5) and start_values.tell() <= value_position:
                interface = self._get_interface_val(db_data, start_values, actual_values)
                data_struct.append(interface)
        except (StreamNotEnoughData, RecursionError):
            pass
        self._aggregated_buffer["body_parse"] = data_struct

    def parse(self, br) -> Dict:
        br = BinaryReader(br)
        if not (br.read(char) == b'p' and br.read(char) == b'p'):
            raise Exception('BadBlockMagic')
        self.parse_block_header_metadata(br)
        if "DB" in self._aggregated_buffer['type']:
            self.parse_db_block_metadata(br)
            if "body" in self._aggregated_buffer:
                self.parse_db_block_body()
        else:
            self.parse_non_db_block_metadata(br)
            self.parse_non_db_block_segement()

        # footer
        br.seek(HEADER_SIZE * (-1), 2)
        self.parse_block_footer_metadata(br)

        return self._aggregated_buffer

    def _get_interface_val(self, db_data, start_values, actual_values):
        data_t = db_data.read(ubyte)
        data_type = DATA_BLOCK_PARAMS_TYPE.get(data_t, 'Attribute ID %s' % hex(data_t))
        param_t = db_data.read(ubyte)
        param_type = PARAMETERS_TYPE.get(param_t, 'Attribute ID %s' % hex(param_t))
        if "ex" in param_type:
            db_data.read(ubyte)
        value = None
        act_val = None

        if "_Init" in param_type:
            if data_type in ('INT', 'WORD', 'DATE', 'S5TIME'):
                value = start_values.read(uint16)
                act_val = actual_values.read(uint16be)
            elif data_type in ('CHAR', 'BOOL', 'BYTE'):
                value = start_values.read(ubyte)
                act_val = actual_values.read(ubyte)
            elif data_type in ('DWORD', 'DINT', 'TIME_OF_DAY', 'TIME'):
                value = start_values.read(uint32)
                act_val = actual_values.read(uint32)
            elif data_type in ('REAL',):
                value = start_values.read(floatbe)
                act_val = actual_values.read(floatbe)
            elif data_type in ('DATE_AND_TIME',):
                value = start_values.read(uint64)
                act_val = actual_values.read(uint64)
            elif data_type in ('STRING',):
                value = self.read_string_by_type(start_values, ubyte)
                act_val = self.read_string_by_type(actual_values, ubyte)
        elif data_type in ('ARRAY',):
            value = []
            array_dim = db_data.read(ubyte)
            db_data.seek(3 + 4 * array_dim)
        elif data_type in ('STRUCT',):
            childs = db_data.read(ubyte)
            if childs == 255:
                childs = db_data.read(uint16)
            value = []
            for i in range(childs):
                value.append(self._get_interface_val(db_data, start_values, actual_values))
        else:
            if data_type in ('INT', 'WORD', 'DATE', 'S5TIME') and len(actual_values) >= 2:
                act_val = actual_values.read(uint16be)
            elif data_type in ('CHAR', 'BOOL', 'BYTE') and len(actual_values) >= 1:
                act_val = actual_values.read(ubyte)
            elif data_type in ('DWORD', 'DINT', 'TIME_OF_DAY', 'TIME') and len(actual_values) >= 4:
                act_val = actual_values.read(uint32)
            elif data_type in ('REAL',) and len(actual_values) >= 2:
                act_val = actual_values.read(floatbe)
            elif data_type in ('DATE_AND_TIME',) and len(actual_values) >= 8:
                act_val = actual_values.read(uint64)
            elif data_type in ('STRING',):
                act_val = self.read_string_by_type(actual_values, ubyte)

        return (data_type, param_type, value, act_val)
