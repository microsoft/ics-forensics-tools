from collections import defaultdict

from typing import Any

from forensic.plugins.s7.s7_szl import SZL_MAP
from forensic.common.stream.stream import BinaryWriter, BinaryReader, ubyte, uint16be, DataStruct, \
    ascii_string, dynamic, uint32be, bytesbe, uint16le

ROSCTR_JOB = 0x01
ROSCTR_ERROR_ACK = 0x02
ROSCTR_ACK_DATA = 0x03
ROSCTR_USER_DATA = 0x07

PARAM_FUNCTION_SETUP_COMM = 0xf0
PARAM_FUNCTION_START_UPLOAD = 0x1d
PARAM_FUNCTION_UPLOAD = 0x1e
PARAM_FUNCTION_END_UPLOAD = 0x1f

FUNCTION_TYPE_REQUEST = 4
FUNCTION_TYPE_RESPONSE = 8
FUNCTION_CPU = 4
FUNCTION_BLOCK = 3

SUBFUNCTION_READ_SZL = 0x01
SUBFUNCTION_LIST_BLOCK = 0x01
SUBFUNCTION_LIST_BLOCKS_OF_TYPE = 0x02

YES_LAST_DATA_UNIT = 0x00
NOT_LAST_DATA_UNIT = 0x01

NO_ERROR = 0

BLOCK_TYPE_MAP = {'08': 'OB',
                  '0A': 'DB',
                  '0B': 'SDB',
                  '0C': 'FC',
                  '0D': 'SFC',
                  '0E': 'FB',
                  '0F': 'SFB'}

BLOCK_LANGUAGE_MAP = {0x00: 'Unknown',
                      0x01: 'AWL',
                      0x02: 'KOP',
                      0x03: 'FUP',
                      0x04: 'SCL',
                      0x05: 'DB',
                      0x06: 'GRAPH',
                      0x07: 'SDB',
                      0x08: 'CPU-DB',
                      0x11: 'SDB',
                      0x12: 'SDB',
                      0x29: 'Encrypted'}


def reverse_map_convert(values_map, value):
    ret_val = None

    for key, val in values_map.items():
        if val == value:
            ret_val = key
            break

    if ret_val is None:
        return f'Unknown {value}'

    return ret_val


class S7LayerResponse(DataStruct):
    protocol_id = ubyte
    rosctr = ubyte
    reserved = uint16be
    pdur = uint16be
    param_len = uint16be
    data_len = uint16be
    param = dynamic
    data = dynamic
    error = dynamic

class S7ParamUserData(DataStruct):
    param_head = bytesbe(3)
    internal_param_len = ubyte
    method = ubyte
    function = ubyte
    sub_function = ubyte
    sequence_num = ubyte
    data_unit_ref_num = ubyte
    last_data_unit = ubyte
    error_code = uint16be


class S7Szl(DataStruct):
    szl_id = uint16be
    szl_specific_index = uint16be
    szl_entry_len = uint16be
    szl_entries_count = uint16be
    szl_list = dynamic


class S7ListBlocks(DataStruct):
    entries = dynamic


class S7ListBlocksEntry(DataStruct):
    block_type = ascii_string(2)
    block_count = uint16be


class S7ListBlocksOfTypeEntry(DataStruct):
    block_number = uint16be
    block_flags = ubyte
    block_lang = ubyte


class S7ParamSetupCommunication(DataStruct):
    function = ubyte
    reserved = ubyte
    max_sessions = uint16be
    curr_sessions = uint16be
    pdu_length = uint16be


class S7ParamStartUpload(DataStruct):
    function = ubyte
    status = ubyte
    unk = uint16be
    upload_id = uint32be
    block_size_length = ubyte
    block_size = dynamic


class S7ParamUpload(DataStruct):
    function = ubyte
    status = ubyte
    length = uint16be
    unk = uint16be
    data = dynamic


class S7ParamEndUpload(DataStruct):
    function = ubyte


class S7Request(DataStruct):
    protocol_id = ubyte
    rosctr = ubyte
    reserved = uint16be
    pdur = uint16le
    param_len = uint16be
    data_len = uint16be


class S7ParamUserDataRequest(DataStruct):
    param_head = bytesbe(3)
    internal_param_len = ubyte
    method = ubyte
    function = ubyte
    sub_function = ubyte
    sequence_num = ubyte


class S7ParamUserDataRequestFragmented(DataStruct):
    param_head = bytesbe(3)
    internal_param_len = ubyte
    method = ubyte
    function = ubyte
    sub_function = ubyte
    sequence_num = ubyte
    data_unit_ref_num = ubyte
    last_data_unit = ubyte
    error_code = uint16be


class S7SzlRequest(DataStruct):
    return_code = ubyte
    transport_size = ubyte
    szl_data_length = uint16be
    szl_id = uint16be
    szl_specific_index = uint16be


class S7EmptyRequest(DataStruct):
    return_code = ubyte
    transport_size = ubyte
    length = uint16be


class S7ListBlocksOfType(DataStruct):
    return_code = ubyte
    transport_size = ubyte
    length = uint16be
    block_type = ascii_string(2)


class S7ParamStartUploadRequest(DataStruct):
    function = ubyte
    status = ubyte
    unknown = uint16be
    upload_id = uint32be
    name_length = ubyte


class S7ParamUploadRequest(DataStruct):
    function = ubyte
    status = ubyte
    unknown = uint16be
    upload_id = uint32be


class S7ParamEndUploadRequest(DataStruct):
    function = ubyte
    status = ubyte
    errorcode = uint16be
    upload_id = uint32be


class S7DataFragment(DataStruct):
    return_code = ubyte
    transport_size = ubyte
    length = uint16be
    data = dynamic


class S7Error(Exception):
    pass


class S7ErrorNotImplemented(S7Error):
    pass

class S7ErrorNotPermitted(S7Error):
    pass

class S7ErrorWithBlockType(S7Error):
    pass

class S7ErrorN0BlockNotExists(S7Error):
    pass

class S7ErrorResourceBottleneck(S7Error):
    pass

class S7ErrorInfoNotAvailable(S7Error):
    pass

class S7Parser:
    def __init__(self):
        self._aggregated_buffer = defaultdict(bytes)
        self._pdur = 1

    def parse(self, br: BinaryReader) -> S7LayerResponse:
        layer = S7LayerResponse(br)

        if layer.rosctr in [ROSCTR_ACK_DATA, ROSCTR_ERROR_ACK]:
            layer.error = br.read(uint16be)

            if layer.error == 0xd241:
                raise S7ErrorNotPermitted()

        layer.param = self.parse_param(layer, br)

        if layer.rosctr == ROSCTR_USER_DATA:
            layer.data = self.parse_user_data(layer, br)

        return layer

    def parse_param(self, layer: S7LayerResponse, br: BinaryReader) -> Any:
        param = None

        if layer.param_len > 0:
            if layer.rosctr == ROSCTR_ACK_DATA:
                function = br.peek(ubyte)

                if function == PARAM_FUNCTION_SETUP_COMM:
                    param = S7ParamSetupCommunication(br)
                elif function == PARAM_FUNCTION_START_UPLOAD:
                    param = S7ParamStartUpload(br)
                    block_size = br.read(bytesbe(param.block_size_length)).replace(b'\x00', b'0')
                    param.block_size = int(block_size.decode('ascii', 'replace'))
                elif function == PARAM_FUNCTION_UPLOAD:
                    param = S7ParamUpload(br)
                    param.data = br.read(bytesbe(param.length))
                elif function == PARAM_FUNCTION_END_UPLOAD:
                    param = S7ParamEndUpload(br)

            elif layer.rosctr == ROSCTR_USER_DATA:
                param = S7ParamUserData(br)

                if param.error_code == 0x8104:
                    raise S7ErrorNotImplemented(f'function {hex(param.function)},' +
                                                f'subfunction {hex(param.sub_function)}')
                elif param.error_code == 0xd203:
                    raise S7ErrorWithBlockType()
                elif param.error_code == 0xd20E:
                    raise S7ErrorN0BlockNotExists()
                elif param.error_code == 0x8304:
                    raise S7ErrorResourceBottleneck()
                elif param.error_code == 0xd401:
                    raise S7ErrorInfoNotAvailable()
                elif param.error_code != 0:
                    raise S7Error(f'Error {hex(param.error_code)} in function ' +
                                  f'{hex(param.function)}, subfunction {hex(param.sub_function)}')

        return param

    def parse_user_data(self, layer: S7LayerResponse, br: BinaryReader) -> Any:
        data = None

        if layer.param is not None and layer.data_len > 0:
            ref_num = layer.param.data_unit_ref_num
            fragment = S7DataFragment(br)

            seq_num = layer.param.sequence_num
            if seq_num != 0:
                frag_data = br.read(bytesbe(fragment.length))
                self._aggregated_buffer[seq_num] += frag_data

                if not (layer.param.last_data_unit == NOT_LAST_DATA_UNIT and layer.param.sequence_num != 0):
                    br = BinaryReader(self._aggregated_buffer[seq_num])
                    del self._aggregated_buffer[seq_num]

            if not (layer.param.last_data_unit == NOT_LAST_DATA_UNIT and layer.param.sequence_num != 0):
                func_parsers = {(FUNCTION_CPU, SUBFUNCTION_READ_SZL): self.parse_szl_data,
                                (FUNCTION_BLOCK, SUBFUNCTION_LIST_BLOCK): self.parse_list_blocks_data,
                                (FUNCTION_BLOCK, SUBFUNCTION_LIST_BLOCKS_OF_TYPE): self.parse_list_blocks_of_type_data}

                func = layer.param.function & 0x0F
                if (func, layer.param.sub_function) in func_parsers:
                    data = func_parsers[(func, layer.param.sub_function)](br, fragment)

        return data

    def parse_szl_data(self, br: BinaryReader, fragment: S7DataFragment) -> S7Szl:
        res = S7Szl(br)
        res.szl_list = []

        for _ in range(res.szl_entries_count):
            index = br.peek(uint16be)
            szl_id = res.szl_id & 0xFF

            if (szl_id, index) in SZL_MAP:
                res.szl_list.append(SZL_MAP[(szl_id, index)](br))
            elif res.szl_id in SZL_MAP:
                res.szl_list.append(SZL_MAP[res.szl_id](br))
            else:
                br.read(bytesbe(res.szl_entry_len))

        return res

    def parse_list_blocks_data(self, br: BinaryReader, fragment: S7DataFragment) -> S7ListBlocks:
        res = S7ListBlocks(br)
        res.entries = []

        for _ in range(fragment.length // 4):
            entry = S7ListBlocksEntry(br)

            if entry.block_type in BLOCK_TYPE_MAP:
                entry.block_type = BLOCK_TYPE_MAP[entry.block_type]

            res.entries.append(entry)

        return res

    def parse_list_blocks_of_type_data(self, br: BinaryReader, fragment: S7DataFragment) -> S7ListBlocks:
        res = S7ListBlocks(br)
        res.entries = []

        for _ in range(fragment.length // 4):
            entry = S7ListBlocksOfTypeEntry(br)

            if entry.block_lang in BLOCK_LANGUAGE_MAP:
                entry.block_lang = BLOCK_LANGUAGE_MAP[entry.block_lang]

            res.entries.append(entry)

        return res

    def write_header(self, rosctr: int, param: BinaryWriter = BinaryWriter(),
                     data: BinaryWriter = BinaryWriter()) -> BinaryWriter:
        bw = BinaryWriter()
        bw.write_struct(S7Request, {'protocol_id': 0x32,
                                    'rosctr': rosctr,
                                    'reserved': 0,
                                    'pdur': self._pdur,
                                    'param_len': len(param),
                                    'data_len': len(data)})
        self._pdur += 1

        return bw + param + data

    def write_setup_communication(self) -> BinaryWriter:
        param = BinaryWriter()
        param.write_struct(S7ParamSetupCommunication, {'function': PARAM_FUNCTION_SETUP_COMM,
                                                       'reserved': 0,
                                                       'max_sessions': 1,
                                                       'curr_sessions': 1,
                                                       'pdu_length': 480})
        return self.write_header(ROSCTR_JOB, param)

    def build_user_data(self, function: int, sub_function: int) -> BinaryWriter:
        bw = BinaryWriter()
        bw.write_struct(S7ParamUserDataRequest, {'param_head': b'\x00\x01\x12',
                                                 'internal_param_len': 4,
                                                 'method': 0x11,
                                                 'function': 0x40 | function,
                                                 'sub_function': sub_function,
                                                 'sequence_num': 0})
        return bw

    def build_user_data_fragmented(self, function: int, sub_function: int,
                                   sequence_num: int, data_unit_ref_num: int = 0) -> BinaryWriter:
        bw = BinaryWriter()
        bw.write_struct(S7ParamUserDataRequestFragmented, {'param_head': b'\x00\x01\x12',
                                                           'internal_param_len': 8,
                                                           'method': 0x12,
                                                           'function': 0x40 | function,
                                                           'sub_function': sub_function,
                                                           'sequence_num': sequence_num,
                                                           'data_unit_ref_num': data_unit_ref_num,
                                                           'last_data_unit': 0,
                                                           'error_code': 0})
        return bw

    def build_user_data_packet(self, function: int, sub_function: int,
                               data: BinaryWriter = None, sequence_num: int = 0) -> BinaryWriter:
        if sequence_num == 0:
            param = self.build_user_data(function, sub_function)
        else:
            param = self.build_user_data_fragmented(function, sub_function, sequence_num)

            data = BinaryWriter()
            data.write_struct(S7DataFragment, {'return_code': 0x0a,
                                               'transport_size': 0,
                                               'length': 0})

        return self.write_header(ROSCTR_USER_DATA, param, data)

    def write_read_szl(self, szl_id: int, szl_index: int = 0, sequence_num: int = 0) -> BinaryWriter:
        if szl_index != 0:
            szl_id = szl_id | 0x100

        data = BinaryWriter()
        data.write_struct(S7SzlRequest, {'return_code': 0xff,
                                         'transport_size': 9,
                                         'szl_data_length': 4,
                                         'szl_id': szl_id,
                                         'szl_specific_index': szl_index})

        return self.build_user_data_packet(FUNCTION_CPU, SUBFUNCTION_READ_SZL, data, sequence_num)

    def write_list_blocks(self, sequence_num: int = 0) -> BinaryWriter:
        data = BinaryWriter()
        data.write_struct(S7EmptyRequest, {'return_code': 0x0a,
                                           'transport_size': 0,
                                           'length': 0})

        return self.build_user_data_packet(FUNCTION_BLOCK, SUBFUNCTION_LIST_BLOCK, data, sequence_num)

    def write_list_blocks_of_type(self, block_type: str, sequence_num: int = 0) -> BinaryWriter:
        converted_block_type = reverse_map_convert(BLOCK_TYPE_MAP, block_type)
        data = BinaryWriter()
        data.write_struct(S7ListBlocksOfType, {'return_code': 0xff,
                                               'transport_size': 9,
                                               'length': 2,
                                               'block_type': converted_block_type})

        return self.build_user_data_packet(FUNCTION_BLOCK, SUBFUNCTION_LIST_BLOCKS_OF_TYPE, data, sequence_num)

    def write_start_upload(self, block_type: str, block_num: int) -> BinaryWriter:
        converted_block_type = reverse_map_convert(BLOCK_TYPE_MAP, block_type)
        block_name = bytes('_%s%05dA' % (converted_block_type, block_num), 'ascii')

        param = BinaryWriter()
        param.write_struct(S7ParamStartUploadRequest, {'function': PARAM_FUNCTION_START_UPLOAD,
                                                       'status': 0,
                                                       'unknown': 0,
                                                       'upload_id': 0,
                                                       'name_length': len(block_name)})
        param.write(bytesbe(len(block_name)), block_name)
        return self.write_header(ROSCTR_JOB, param)

    def write_upload(self, upload_id: int) -> BinaryWriter:
        param = BinaryWriter()
        param.write_struct(S7ParamUploadRequest, {'function': PARAM_FUNCTION_UPLOAD,
                                                  'status': 0,
                                                  'unknown': 0,
                                                  'upload_id': upload_id})

        return self.write_header(ROSCTR_JOB, param)

    def write_end_upload(self, upload_id: int) -> BinaryWriter:
        param = BinaryWriter()
        param.write_struct(S7ParamEndUploadRequest, {'function': PARAM_FUNCTION_END_UPLOAD,
                                                     'status': 0,
                                                     'errorcode': 0,
                                                     'upload_id': upload_id})

        return self.write_header(ROSCTR_JOB, param)
