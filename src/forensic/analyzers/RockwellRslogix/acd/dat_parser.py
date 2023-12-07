from forensic.common.stream.stream import DataStruct, uint16, uint32, bytesbe, ascii_string, dynamic


class DatHeader(DataStruct):
    file_size = uint32
    unknown = uint32
    end_of_content_offset = uint32
    records_header_offset = uint32
    unknown2 = uint32
    record_amount = uint32
    record_amount2 = uint32


class RecordsHeader(DataStruct):
    signature = bytesbe(2)
    header_size = uint32
    unknown = uint32
    unknown2 = uint32
    metadata_offset = uint32
    first_record_offset = uint32
    unknown3 = dynamic


class Rung(DataStruct):
    signature = bytesbe(2)
    struct_size = uint32
    remaining_length = uint32
    flag = uint16
    uid = uint32
    name = ascii_string(41)
    rung_size = uint32
    rung_content = dynamic


# class Component (DataStruct):
#     signature = bytesbe(2)
#     struct_size = uint32
#     remaining_length = uint32
#     flag = uint32
#     status = uint32
#     uid = uint32
#     parent_uid = uint32
#     name = bytesbe(0x52)
#     version_number = uint16
#     ioi = bytesbe(12)
#     physical_address = uint32
#     first_dim = uint32
#     second_dim = uint32
#     third_dim = uint32
#     bit_offset = uint32
#     data_type_uid = uint32
#     display_style = bytesbe(4)
#     target_uid = uint32
#     target_physical_address = uint32
#     component_type = uint32
#     component_subtype = uint32
#     asa_type = bytesbe(4)
#     base_uid = uint32
#     variable_portion_size = uint32
#     variable_portion = dynamic

class Component(DataStruct):
    signature = bytesbe(2)
    struct_size = uint32
    remaining_length = uint32
    flag = uint32
    status = uint32
    unknown = uint32
    uid = uint32
    parent_uid = uint32
    name = bytesbe(0x7c)
    unknown2 = uint32
    unknown3 = uint32
    version_number = uint16
    ioi = bytesbe(12)
    physical_address = uint32
    first_dim = uint32
    second_dim = uint32
    third_dim = uint32
    bit_offset = uint32
    data_type_uid = uint32
    display_style = bytesbe(4)
    target_uid = uint32
    target_physical_address = uint32
    component_type = uint32
    component_subtype = uint32
    asa_type = bytesbe(4)
    base_uid = uint32
    variable_portion_size = uint32
    variable_portion = dynamic


class UnknownRecord(DataStruct):
    signature = bytesbe(2)
    struct_size = uint32
    unknown = dynamic


class RegionLink(DataStruct):
    flag = uint16
    user_flag = uint32
    region_id = uint32
    parent_uid = uint32
    uid = uint32
    next_uid = uint32


class Routine:
    def __init__(self, uid: int, name: str, program_uid: int, rung: Rung):
        self.uid = uid
        self.name = name
        self.program_uid = program_uid
        self.rungs = []
        self.add_rung(rung)

    def add_rung(self, rung: Rung):
        self.rungs.append(rung)

    def get_code(self) -> str:
        code = ""
        for rung in self.rungs:
            code += rung.rung_content
        return code


class Tag:
    def __init__(self, uid: int, name: str) -> None:
        self.uid = uid
        self.name = name


class Program:
    def __init__(self, uid: int, name: str) -> None:
        self.uid = uid
        self.name = name
        self.routines = []
        self.tags = []

    def add_routine(self, routine: Routine):
        self.routines.append(routine)

    def add_tag(self, tag: Tag):
        self.tags.append(tag)


class Controller:
    def __init__(self, name: str, programs: list = [], tags: list = []) -> None:
        self.name = name
        self.programs = programs
        self.tags = tags

    def add_program(self, program: Program):
        self.programs.append(program)

    def add_tag(self, tag: Tag):
        self.tags.append(tag)


component_types = {
    "ProgramModule": 0x68,
    "Device": 0x69,
    "Data": 0x6a,
    "Tag": 0x6b,
    "DataType": 0x6c,
    "Routine": 0x6d,
    "ERRD": 0x6e,
    "Task": 0x70,
    "MapConnection": 0x7e,
    "Label": 0x8c,
    "Msg": 0x8d,
    "Controller": 0x8e,
    "MotionGroup": 0xb0,
    "Trend": 0xb2,
    "AddOnInstruction": 0x338,
}
