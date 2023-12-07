from forensic.common.stream.stream import (DataStruct, uint16be, uint16le, uint32be, bytesne,
                                           nt_ascii_string, ubyte, uint64be)


class S7COMMSzl_11_1(DataStruct):
    index = uint16be
    module = nt_ascii_string(20)
    module_type = uint16be
    version = uint16be
    release = uint16be


class S7COMMSzl_11_7(DataStruct):
    index = uint16be
    module = nt_ascii_string(20)
    module_type = uint16be
    version = uint16be
    release = uint16be


class S7COMMSzl_1C_1(DataStruct):
    index = uint16be
    plc_name = nt_ascii_string(32)


class S7COMMSzl_1C_2(DataStruct):
    index = uint16be
    module_name = nt_ascii_string(32)

class S7COMMSzl_1C_3(DataStruct):
    index = uint16be
    plant_identification = nt_ascii_string(32)


class S7COMMSzl_1C_4(DataStruct):
    index = uint16be
    copyright = nt_ascii_string(32)


class S7COMMSzl_1C_5(DataStruct):
    index = uint16be
    serial_number = nt_ascii_string(32)


class S7COMMSzl_1C_7(DataStruct):
    index = uint16be
    module_type_name = nt_ascii_string(32)


class S7COMMSzl_1C_8(DataStruct):
    index = uint16be
    serial_number_memory_card = nt_ascii_string(32)


class S7COMMSzl_1C_9(DataStruct):
    index = uint16be
    manufacturer_id = uint16be
    profile_id = uint16le
    profile_spec_tye = uint16be
    reserved = bytesne(26)


class S7COMMSzl_1C_A(DataStruct):
    index = uint16be
    oem_copyright = nt_ascii_string(26)
    oem_id = uint16be
    oem_additional_id = uint32be


class S7COMMSzl_1C_B(DataStruct):
    index = uint16be
    location = nt_ascii_string(32)


class S7COMMSzl_32_4(DataStruct):
    index = uint16be
    key = uint16be
    param = uint16be
    real_state = uint16be
    key_state = uint16be
    unk = bytesne(30)

class S7COMMSzl_31_3(DataStruct):
    index = uint16be
    cycling_flags = ubyte
    io_flags = ubyte
    data_flags = ubyte
    timer_flags = ubyte
    unk1 = uint16be
    unk2 = uint16be
    unk3 = uint16be
    unk4 = uint16be

class S7COMMSzl_0(DataStruct):
    szl_id = uint16be

class S7COMMSzl_424(DataStruct):
    unk1 = uint16be
    unk2 = ubyte
    plc_run_mode = ubyte
    unk3 = uint32be
    unk4 = ubyte
    unk5 = ubyte
    unk6 = ubyte
    unk7 = ubyte
    unk8 = uint64be

SZL_ID_LIST_ALL = 0
SZL_ID_IDENTIFICATION = 0x11
SZL_ID_COMPONENT_IDENTIFICATION = 0x1C
SZL_ID_COMMUNICATION_STATUS = 0x32

SZL_MAP = {SZL_ID_LIST_ALL: S7COMMSzl_0,
           (SZL_ID_IDENTIFICATION, 1): S7COMMSzl_11_1,
           (SZL_ID_IDENTIFICATION, 7): S7COMMSzl_11_7,
           (SZL_ID_COMPONENT_IDENTIFICATION, 1): S7COMMSzl_1C_1,
           (SZL_ID_COMPONENT_IDENTIFICATION, 2): S7COMMSzl_1C_2,
           (SZL_ID_COMPONENT_IDENTIFICATION, 3): S7COMMSzl_1C_3,
           (SZL_ID_COMPONENT_IDENTIFICATION, 4): S7COMMSzl_1C_4,
           (SZL_ID_COMPONENT_IDENTIFICATION, 5): S7COMMSzl_1C_5,
           (SZL_ID_COMPONENT_IDENTIFICATION, 7): S7COMMSzl_1C_7,
           (SZL_ID_COMPONENT_IDENTIFICATION, 8): S7COMMSzl_1C_8,
           (SZL_ID_COMPONENT_IDENTIFICATION, 9): S7COMMSzl_1C_9,
           (SZL_ID_COMPONENT_IDENTIFICATION, 0xa): S7COMMSzl_1C_A,
           (SZL_ID_COMPONENT_IDENTIFICATION, 0xb): S7COMMSzl_1C_B,
           (SZL_ID_COMMUNICATION_STATUS, 4): S7COMMSzl_32_4,
           (0x31, 0x3): S7COMMSzl_31_3,
           0x424: S7COMMSzl_424}

SZL_INDEX_NAMES = {
    'szl_0011':
        {
            1: 'module_identification',
            7: 'basic_firmware_identification'
        },
    'szl_001C': {
        1: 'module_identification',
        2: 'module_name',
        3: 'module_plant_designation',
        4: 'copyright',
        5: 'module_serial_number',
        7: 'module_type_name',
        8: 'serial_number_memory_card',
        9: 'cpu_model_manufacturer_and_profile',
        0xa: 'model_oem_id',
        0xb: 'module_location_id'
    },
    'szl_0032': {
        4: 'object_management_system_status',
        3: 'operator_interface_O_I'
    },
    'szl_0424': {
        -1: 'current_mode_transition'
    }
}