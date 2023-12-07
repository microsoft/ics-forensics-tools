import inspect

from typing import List

from forensic.analyzers.CodeSysV3 import tag_handlers
from forensic.analyzers.CodeSysV3.tag_handlers import CodesysBaseTag, CodesysUnknownTag, CodesysV3FileFormatAbstract
from forensic.common.stream.stream import BinaryReader, ubyte, bytesbe, uint16be, uint16le, uint32le

'''TAG_LIST_OF_TAGS = 0x81
TAG_APPLICATION_NAME = 0x10
TAG_LIST_OF_CODE_AREAS = 0x82
TAG_CODE_AREA = 0xA0
TAG_CODE_AREA_HEADER = 0x21
TAG_CODE_AREA_DATA = 0x22
TAG_PROJECT_INFO = 0x87
TAG_FUNCTION_SYMBOLS = 0x88
TAG_FOOTER_ADDRESSES = 0x86

TAG_SYMBOLS = 0x85
TAG_SYMBOL = 0x50
TAG_SYMBOL_EXTENDED = 0x80

TAG_INIT_JUMP_TABLE = 0x60
TAG_ENTRY_POINT = 0x61
TAG_INIT_APPLICATION = 0x63
TAG_INTERNAL_SYMBOL_TABLE_START = 0x6f
TAG_INTERNAL_SYMBOL_TABLE_END = 0x71'''

HANDLER_SET_OPERATION_STATE = 3
HANDLER_APP_UPLOAD_FULL_APLLICATION = 5


class CodesysV3FileFormat(CodesysV3FileFormatAbstract):
    def __init__(self):
        self._classes = self._find_classes()

    def _find_classes(self):
        classes = inspect.getmembers(tag_handlers, inspect.isclass)
        return {cls.tid: cls for name, cls in classes if issubclass(cls, CodesysBaseTag)}

    def extract_tag_encoded_data(self, br: BinaryReader) -> int:
        res = 0

        for counter in range(6):
            curr_byte = br.read(ubyte)
            res |= (curr_byte & 0x7f) << (counter * 7)
            if curr_byte <= 0x7f:
                break

        return res

    def read_tag(self, br: BinaryReader) -> CodesysBaseTag:
        tag_id = self.extract_tag_encoded_data(br)
        tag_size = self.extract_tag_encoded_data(br)
        tag_data = br.read(bytesbe(tag_size))

        return self.parse_tag(tag_id, tag_data)

    def parse_tag(self, tag_id: int, tag_data: bytes) -> CodesysBaseTag:
        tag = CodesysUnknownTag()
        tag.tid = tag_id
        tag.data = tag_data

        if tag_id in self._classes:
            tag = self._classes[tag_id](self, tag_data)

        return tag

    def read_list_of_tags(self, tag_data: bytes) -> List[CodesysBaseTag]:
        tags = []

        br_data = BinaryReader(tag_data)

        while br_data.remaining_data() > 0:
            tag = self.read_tag(br_data)
            tags.append(tag)

        return tags

    def read_section(self, br: BinaryReader):
        sig = br.read(uint16be)

        if sig == 0x55CD:
            some_size = br.read(uint16le)
            br.read(uint16le)
            handler_id = br.read(uint16le)
            br.read(uint32le)  # app_session_id
            section_size = br.read(uint32le)
            if some_size + 4 > 0x010:
                br.read(uint32le)  # unk
            data = br.read(bytesbe(section_size))

            return handler_id, data

        return None, None

    def parse(self, file_data):
        all_tags = []
        br = BinaryReader(file_data)

        all_tags += [self.read_tag(br)]

        while br.remaining_data() > 0:
            handler_id, data = self.read_section(br)
            if handler_id == HANDLER_SET_OPERATION_STATE:
                all_tags += [self.read_tag(BinaryReader(data))]
            elif handler_id == HANDLER_APP_UPLOAD_FULL_APLLICATION:
                all_tags += self.read_list_of_tags(data)

        return all_tags
