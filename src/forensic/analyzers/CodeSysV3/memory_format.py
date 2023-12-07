from datetime import datetime

from forensic.analyzers.CodeSysV3.armv7.arm_sim import MemoryStream
from forensic.analyzers.CodeSysV3.tag_handlers import CodesysListOfCodeAreas, CodesysInitJumpTable, \
    CodesysInitApplication, CodesysEntryPoint, CodesysInternalTableSymbolStart, CodesysInternalTableSymbolEnd, \
    CodesysFooterAddresses, CodesysSymbols, CodesysSymbol, CodesysFunctionSymbols, CodesysProjectInfo
from forensic.common.stream.stream import bytesbe


class CodesysV3MemoryFormat:
    def __init__(self, file_data, all_tags):
        self._file_data = file_data
        self._all_tags = all_tags
        self.all_code_blocks = self.extract_all_code(self._all_tags)
        self.memory_file = self.reconstruct_memory_file(self.all_code_blocks)
        self.imp_addr = self.extract_important_addresses(self._all_tags)
        self.symbols = self.extract_symbols(self._all_tags)
        self.symbols.update(self.imp_addr)
        self.project_info = self.extract_project_info(self._all_tags)

    def extract_all_code(self, all_tags):
        all_code_blocks = {}
        for tag in all_tags:
            if isinstance(tag, CodesysListOfCodeAreas):
                for ca in tag.sub_areas:
                    all_code_blocks[ca.pointer] = ca.code

        return all_code_blocks

    def reconstruct_memory_file(self, all_code):
        ms = MemoryStream()

        for pointer in sorted(all_code.keys()):
            ms.seek(pointer)
            ms.write(bytesbe(len(all_code[pointer])), all_code[pointer])

        return ms.dump()

    def extract_important_addresses(self, all_tags):
        res = {}
        dict_important_addresses_tags = {CodesysInitJumpTable: '@init_jump_table',
                                         CodesysInitApplication: '@init_application',
                                         CodesysEntryPoint: '@entry_point',
                                         CodesysInternalTableSymbolStart: '@table_start',
                                         CodesysInternalTableSymbolEnd: '@table_end'}
        for tag in all_tags:
            if isinstance(tag, CodesysFooterAddresses):
                for sub_tag in tag.sub_tags:
                    if type(sub_tag) in dict_important_addresses_tags:
                        res[dict_important_addresses_tags[type(sub_tag)]] = sub_tag.pointer

        return res

    def extract_symbols(self, all_tags):
        res = {}
        for tag in all_tags:
            if isinstance(tag, CodesysSymbols):
                for symbol in tag.symbols:
                    if isinstance(symbol, CodesysSymbol):
                        res[symbol.pointer] = symbol.name.decode('ascii', 'replace')
            if isinstance(tag, CodesysFunctionSymbols):
                for pointer in tag.symbols:
                    res[pointer] = tag.symbols[pointer]['name'].decode('ascii', 'replace')

        return res

    def extract_project_info(self, all_tags):
        project_info = {}
        for tag in all_tags:
            if isinstance(tag, CodesysProjectInfo):
                for attr in tag.attributes:
                    attr_value = tag.attributes.get(attr)
                    if type(attr_value) == datetime:
                        attr_value = str(attr_value)
                    elif type(attr_value) == int:
                        pass
                    else:
                      attr_value = attr_value.decode()
                    project_info[attr] = attr_value

        return project_info
