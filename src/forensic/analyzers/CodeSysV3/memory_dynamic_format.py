from forensic.analyzers.CodeSysV3.armv7.arm_sim import ArmMachineSimulator
from forensic.common.stream.stream import DataStruct, uint32le, uint16le, ubyte, bytesbe, BinaryReader, nt_ascii_string
from typing import Type, List

class CodesysInternalSymbolTableHeader(DataStruct):
    size = uint32le
    unk0 = uint32le
    prog_calls_pous_count = uint16le
    structs_count = uint16le
    vals_structs_count = uint16le
    lib_pous_count = uint16le
    methods_count = uint16le
    system_funcs_count = uint16le


class CodesysProgCallsPouSymbol(DataStruct):
    unk0 = uint32le
    unk1 = uint32le
    table_offset = uint32le
    pointer_type_0 = uint16le
    pointer_type_1 = uint16le
    pointer = uint32le
    pointer_offset = uint32le


class CodesysStructSymbol(DataStruct):
    checksum = uint32le
    table_offset = uint32le


class CodesysValStructSymbol(DataStruct):
    checksum = uint32le
    table_offset = uint32le


class CodesysValStructSymbol(DataStruct):
    checksum = uint32le
    table_offset = uint32le


class CodesysUnknown24Symbol(DataStruct):
    unk0 = bytesbe(8)
    table_offset = uint32le
    unk1 = bytesbe(0x18)


class CodesysMethodSymbol(DataStruct):
    unk0 = uint32le
    unk1 = uint32le
    table_offset = uint32le
    pointer_type_0 = uint16le
    pointer_type_1 = uint16le
    pointer = uint32le
    pointer_offset = uint32le
    zero = uint32le


class CodesysLibSymbol(DataStruct):
    table_offset = uint32le

class CodesysTaskInfo(DataStruct):
    dwVersion = uint32le
    pszName = uint32le
    nPriority = uint16le
    KindOfTask = uint16le
    bWatchdog = ubyte
    bProfiling = ubyte
    _padding = uint16le
    dwEventFunctionPointer = uint32le
    pszExternalEvent = uint32le
    dwTaskEntryFunctionPointer = uint32le
    dwWatchdogSensitivity = uint32le
    dwInterval = uint32le
    dwWatchdogTime = uint32le
    dwCycleTime = uint32le
    dwAverageCycleTime = uint32le
    dwMaxCycleTime = uint32le
    dwMinCycleTime = uint32le
    iJitter = uint32le
    iJitterMin = uint32le
    iJitterMax = uint32le
    dwCycleCount = uint32le
    iState = uint16le
    wNumOfJitterDistributions = uint16le
    pJitterDistribution = uint32le
    bTimeSlicing = ubyte
    byDummy = ubyte
    wDummy = uint16le
    dwIECCycleCount = uint32le
    unk0 = uint32le
    unk1 = uint32le

class CodesysTaskStruct(DataStruct):
    unk_zero = uint16le
    taskinfo_count = uint16le
    app_name_pointer = uint32le
    taskinfo_arr_pointer = uint32le

def memcopy(ms: ArmMachineSimulator):
    offset_stack = 0
    # Canary stuff
    if ms.read_mem(ms.get_reg('sp'), uint32le) == 0xCDE1F2CD:
        offset_stack = 8
    dst = ms.read_mem(ms.get_reg('sp') + offset_stack, uint32le)
    src = ms.read_mem(ms.get_reg('sp') + offset_stack + 4, uint32le)
    size = ms.read_mem(ms.get_reg('sp') + offset_stack + 8, uint32le)
    ms.write_mem(dst, bytesbe(size), ms.read_mem(src, bytesbe(size)))


def sys_setup_tasks(ms: ArmMachineSimulator):
    offset_stack = 0
    # Canary stuff
    if ms.read_mem(ms.get_reg('sp'), uint32le) != 0xCDE1F2CD:
        offset_stack = -8
    ms.function_storage['task_struct'] = ms.read_mem(ms.get_reg('sp') + offset_stack - 4, uint32le)

    # Finish execution, we got what we need
    ms.set_reg('lr', 0xFFFFFFFE)

class CodesysV3MemoryDynamicFormat:
    def __init__(self):
        self.taskinfos = []
        self.g_entry_point = None

    def read_structs(self, br: BinaryReader, struct_class: Type[DataStruct], count: int) -> List[DataStruct]:
        res = []

        for _ in range(count):
            res.append(br.read_struct(struct_class))

        return res

    def get_key_by_value(self, d, value):
        for key, val in d.items():
            if val == value:
                return key
        return None

    def simplify_internal_symbols(self, obj_struct):
        res = {}
        for dtype, list_items in obj_struct.items():
            for item in list_items:
                if 'name' in item:
                    if 'pointer' in item:
                        res[item['pointer']] = item['name']
                    if 'pointer_offset' in item:
                        res[item['pointer_offset']] = item['name']

        return res

    def extract_internal_symbols(self, br: BinaryReader, imp_addr: dict):
        br.seek(imp_addr['@table_start'])

        symbol_table_header = br.read_struct(CodesysInternalSymbolTableHeader)
        obj_struct = {}
        obj_struct['prog_calls_pous'] = self.read_structs(br, CodesysProgCallsPouSymbol,
                                                     symbol_table_header['prog_calls_pous_count'])
        obj_struct['structs'] = self.read_structs(br, CodesysStructSymbol, symbol_table_header['structs_count'])
        obj_struct['vals_structs'] = self.read_structs(br, CodesysValStructSymbol, symbol_table_header['vals_structs_count'])
        obj_struct['lib_pous'] = self.read_structs(br, CodesysUnknown24Symbol, symbol_table_header['lib_pous_count'])
        obj_struct['methods'] = self.read_structs(br, CodesysMethodSymbol, symbol_table_header['methods_count'])
        obj_struct['system_funcs'] = self.read_structs(br, CodesysLibSymbol, symbol_table_header['system_funcs_count'])

        current_offset = br.tell() - imp_addr['@table_start']
        footer = br.read(bytesbe(symbol_table_header['size'] - current_offset))
        fstrings = BinaryReader(footer)

        for dtype, list_items in obj_struct.items():
            for item in list_items:
                if 'table_offset' in item:
                    fstrings.seek(item['table_offset'])
                    sfound = fstrings.read(bytesbe(fstrings.remaining_data()))
                    item['name'] = sfound[:sfound.find(b'\x00')].decode('ascii')

        return obj_struct

    def parse(self, br_memory, imp_addr):
        internal_symbols = self.extract_internal_symbols(br_memory, imp_addr)
        return self.simplify_internal_symbols(internal_symbols)

    def validate_supported_arch(self, br_memory, imp_addr):
        arch = None
        br_memory.seek(imp_addr['@init_jump_table'])
        if br_memory.read(bytesbe(4)) == b'\x00\x44\x2D\xE9':
            arch = 'armle'

        return arch == 'armle'

    def hook_functions(self, ams, symbols):
        ams.add_patch_function('__SYS__SETUP__TASKS', self.get_key_by_value(symbols, '__SYS__SETUP__TASKS'),
                               sys_setup_tasks)
        ams.add_patch_function('__MEMCOPY', self.get_key_by_value(symbols, '__MEMCOPY'), memcopy)

    def get_cycle_grandparent_function_address(self, ams, symbols, imp_addr, all_code):
        # entry_point holds the offset that holds the function pointer, we need to resolve it
        entry_point = ams.read_mem(imp_addr['@entry_point'], uint32le)
        self.g_entry_point = ams.xref_graph(all_code, symbols, entry_point)

        # We need to find the functions that are referring to cycles
        task_create_funcs = set()
        for connected_edge, cycle in self.g_entry_point.in_edges('__SYS__RTS__CYCLE__2'):
            for task_create, connected_edge in self.g_entry_point.in_edges(connected_edge):
                task_create_funcs.add(task_create)
        return int(list(task_create_funcs)[0], 16)

    def get_task_create_parent_function(self, ams, symbols, imp_addr, all_code):
        entry_point = ams.read_mem(imp_addr['@init_application'], uint32le)
        g_entry_point = ams.xref_graph(all_code, symbols, entry_point)

        # We need to find the functions that are referring to tasks
        task_setup_funcs = set()
        for connected_edge, cycle in g_entry_point.in_edges('__SYS__SETUP__TASKS'):
            task_setup_funcs.add(connected_edge)
        return int(list(task_setup_funcs)[0], 16)

    def simulate_to_find_taskinfos(self, memory_file, symbols, imp_addr, all_code):
        ams = ArmMachineSimulator(memory_file)
        self.hook_functions(ams, symbols)

        # Simulate etnry point ot fix the jump table
        ams.simulate_function(imp_addr['@init_jump_table'])
        ams.simulate_function(self.get_cycle_grandparent_function_address(ams, symbols, imp_addr, all_code))
        ams.simulate_function(self.get_task_create_parent_function(ams, symbols, imp_addr, all_code))

        task_struct = ams.read_struct(ams.function_storage['task_struct'], CodesysTaskStruct)

        task_info_ptrs = []
        for task_no in range(task_struct['taskinfo_count']):
            task_info_ptrs.append(ams.read_mem(task_struct['taskinfo_arr_pointer'] + task_no * 4, uint32le))


        for tinfo_ptr in task_info_ptrs:
            taskinfo = ams.read_struct(tinfo_ptr, CodesysTaskInfo)
            name = ams.read_mem(taskinfo['pszName'], nt_ascii_string(0x33))

            task_entry_function = ams.read_mem(taskinfo['dwTaskEntryFunctionPointer'], uint32le)
            symbols[task_entry_function] = name

            g_task_entry_function = ams.xref_graph(all_code, symbols, task_entry_function)

            self.taskinfos.append({'name': name,
                              'taskinfo': taskinfo,
                              'xrefs': g_task_entry_function})