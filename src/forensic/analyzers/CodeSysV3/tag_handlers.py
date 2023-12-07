import copy
from datetime import datetime

from abc import ABC, abstractmethod
from forensic.common.stream.stream import DataStruct, dynamic, BinaryReader, uint16le, uint32le, bytesbe


class CodesysV3FileFormatAbstract(ABC):
    @abstractmethod
    def read_tag(self, br: BinaryReader):
        pass

    @abstractmethod
    def read_list_of_tags(self, tag_data: bytes):
        pass


class CodesysBaseTag(DataStruct):
    tid = dynamic

    def _null_ending_bytes(self, data: bytes) -> bytes:
        return data[:data.find(b'\x00')]


class CodesysUnknownTag(CodesysBaseTag):
    data = dynamic


class CodesysListOfTags(CodesysBaseTag):
    tid = 0x81
    sub_tags = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.sub_tags = cff.read_list_of_tags(data)


class CodesysApplicationName(CodesysBaseTag):
    tid = 0x10
    name = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.name = self._null_ending_bytes(data)


class CodesysListOfCodeAreas(CodesysBaseTag):
    tid = 0x82
    sub_areas = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.sub_areas = cff.read_list_of_tags(data)


class CodesysCodeAreaHeader(CodesysBaseTag):
    tid = 0x21
    data = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.data = data


class CodesysCodeAreaData(CodesysBaseTag):
    tid = 0x22
    data = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.data = data


class CodesysCodeArea(CodesysBaseTag):
    tid = 0xA0
    area_type = dynamic
    pointer = dynamic
    code = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br_code_area = BinaryReader(data)
        tag_header = cff.read_tag(br_code_area)

        if isinstance(tag_header, CodesysCodeAreaHeader):
            br_pointer = BinaryReader(tag_header.data)
            self.area_type = br_pointer.read(uint16le)
            self.pointer = br_pointer.read(uint32le)

            tag_code = cff.read_tag(br_code_area)

            if isinstance(tag_code, CodesysCodeAreaData):
                br_code = BinaryReader(tag_code.data)
                code_size = br_code.read(uint32le)
                self.code = br_code.read(bytesbe(code_size))


class CodesysProjectInfo(CodesysBaseTag):
    tid = 0x87
    attributes = dynamic
    unknown_tags = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.attributes = {}

        labels = {1: 'name',
                  2: 'project_version',
                  3: 'project_build_datetime',
                  4: 'author',
                  5: 'description',
                  6: 'ide_build_version',
                  8: 'codesys_version'}

        for sub_tag in cff.read_list_of_tags(data):
            if sub_tag.tid in labels:
                if sub_tag.tid == 3:
                    self.attributes[labels[sub_tag.tid]] = datetime.fromtimestamp(
                        int.from_bytes(sub_tag.data, byteorder='little'))
                else:
                    self.attributes[labels[sub_tag.tid]] = self._null_ending_bytes(sub_tag.data)

            else:
                self.attributes[f'unknown_tag {sub_tag.tid}'] = sub_tag.data


class CodesysFunctionSymbols(CodesysBaseTag):
    tid = 0x88
    symbols = dynamic
    unknown_tags = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.symbols = {}
        self.unknown_tags = []

        temp_symbol = None
        for sub_tag in cff.read_list_of_tags(data):
            if sub_tag.tid == 1:
                temp_symbol = {}
                br_sub_tag = BinaryReader(sub_tag.data)
                temp_symbol['type'] = br_sub_tag.read(uint16le)
                temp_symbol['pointer'] = br_sub_tag.read(uint32le)
                temp_symbol['raw'] = br_sub_tag.read(bytesbe(br_sub_tag.remaining_data()))
            elif sub_tag.tid == 2:
                if temp_symbol is None:
                    temp_symbol = {}
                temp_symbol['name'] = self.null_ending_bytes(sub_tag.data)
                self.symbols[temp_symbol['pointer']] = copy.deepcopy(temp_symbol)
                temp_symbol = None
            else:
                self.unknown_tags.append({'unknown tag': sub_tag.tid, 'raw': sub_tag.data})


class CodesysFooterAddresses(CodesysBaseTag):
    tid = 0x86
    sub_tags = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.sub_tags = cff.read_list_of_tags(data)


class CodesysInitJumpTable(CodesysBaseTag):
    tid = 0x60
    pointer_type = dynamic
    pointer = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br = BinaryReader(data)
        self.pointer_type = br.read(uint16le)
        self.pointer = br.read(uint32le)


class CodesysSymbols(CodesysBaseTag):
    tid = 0x85
    symbols = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.symbols = cff.read_list_of_tags(data)


class CodesysSymbol(CodesysBaseTag):
    tid = 0x50
    pointer_type = dynamic
    pointer = dynamic
    zeros = dynamic
    name = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br_symbol = BinaryReader(data)
        self.pointer_type = br_symbol.read(uint16le)
        self.pointer = br_symbol.read(uint32le)
        self.zeros = br_symbol.read(uint32le)
        self.name = self._null_ending_bytes(br_symbol.read(bytesbe(br_symbol.remaining_data())))


class CodesysSymbolExtended(CodesysBaseTag):
    tid = 0x88
    pointer_type = dynamic
    pointer = dynamic
    resolve_hash = dynamic
    index = dynamic
    raw = dynamic
    name = dynamic
    unknown_tags = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        self.unknown_tags = []

        for sub_tag in cff.read_list_of_tags(data):
            if sub_tag.tid == 1:
                br_sub_tag = BinaryReader(sub_tag.data)
                self.pointer_type = br_sub_tag.read(uint16le)
                self.pointer = br_sub_tag.read(uint32le)
                self.resolve_hash = br_sub_tag.read(uint32le)
                self.index = br_sub_tag.read(uint32le)
                self.raw = br_sub_tag.read(bytesbe(br_sub_tag.remaining_data()))
            elif sub_tag.tid == 2:
                self.name = self._null_ending_bytes(sub_tag.data)
            else:
                self.unknown_tags.append({'unknown tag': sub_tag.tid, 'raw': sub_tag.data})


class CodesysEntryPoint(CodesysBaseTag):
    tid = 0x61
    pointer_type = dynamic
    pointer = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br = BinaryReader(data)
        self.pointer_type = br.read(uint16le)
        self.pointer = br.read(uint32le)


class CodesysInternalTableSymbolStart(CodesysBaseTag):
    tid = 0x6f
    pointer_type = dynamic
    pointer = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br = BinaryReader(data)
        self.pointer_type = br.read(uint16le)
        self.pointer = br.read(uint32le)


class CodesysInternalTableSymbolEnd(CodesysBaseTag):
    tid = 0x71
    pointer_type = dynamic
    pointer = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br = BinaryReader(data)
        self.pointer_type = br.read(uint16le)
        self.pointer = br.read(uint32le)


class CodesysInitApplication(CodesysBaseTag):
    tid = 0x63
    pointer_type = dynamic
    pointer = dynamic

    def __init__(self, cff: CodesysV3FileFormatAbstract, data: bytes):
        br = BinaryReader(data)
        self.pointer_type = br.read(uint16le)
        self.pointer = br.read(uint32le)
