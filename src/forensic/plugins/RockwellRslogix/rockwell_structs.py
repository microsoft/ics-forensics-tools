from forensic.common.stream.stream import BinaryReader, DataStruct, uint16, uint32, uint16le, bytesbe, dynamic
from enum import Enum

class CipClasses(Enum):
    Identity = 0x01
    ProjectName = 0x64 # Need verification
    Program = 0x68
    Routine = 0x6d
    Tag = 0x6b
    Task = 0x70
    PortObject = 0xf4


class ServiceCodes(Enum):
    GetAttributesAll = 0x01
    GetAttributeList = 0x03
    GetAttributeSingle = 0x0e
    GetAllInstances = 0x4b
    

class AttributesResponse(DataStruct):
    attribute_count = uint16


class Attribute(DataStruct):
    attribute = uint16
    attribute_status = uint16
    data = dynamic


class NameAttribute(DataStruct):
    size = uint16
    name = dynamic


class NameAttribute32(DataStruct):
    size = uint32
    name = dynamic


class AddressAttribute(DataStruct):
    address = uint32


class TypeAttribute(DataStruct):
    type = uint16


class ControlAttribute(DataStruct):
    control = uint32


class SizeAttribute(DataStruct):
    size = uint32


class PortZeroAttributes(DataStruct):
    revision = uint16
    max_instance = uint16
    num_of_instances = uint16
    entry_point = uint16


class PortInstance(DataStruct):
    port_type = uint16
    port_number = uint16


class ProjectNameResponse(DataStruct):
    size = uint16
    name = dynamic


class KeyswitchResponse(DataStruct):
    state = uint16le


class uint32Attribute(DataStruct):
    value = uint32


class uint16Attribute(DataStruct):
    value = uint16


class ProgramInstancesAttribute(DataStruct):
    instances_count = uint16
    instances = dynamic


class Routine:
    def __init__(self, program_instance: int, response: bytes) -> None:
        self.program_instance = program_instance
        self.name = ""
        self.instance = ""
        self.address = 0
        self.type = 0
        self.size = 0
        self.code = b""
        self._parse(response)

    def _parse(self, response: bytes):
        br = BinaryReader(response)
        attributes_response = AttributesResponse(br)
        for i in range(attributes_response.attribute_count):
            attr_response = Attribute(br)
            if attr_response.attribute == routine_attributes["name"]:
                name_attr = NameAttribute32(br)
                self.name = br.read(bytesbe(name_attr.size)).decode()
            elif attr_response.attribute == routine_attributes["type"]:
                type_attr = TypeAttribute(br)
                self.type = type_attr.type
            elif attr_response.attribute == routine_attributes["address"]:
                address_attr = AddressAttribute(br)
                self.address = address_attr.address
            elif attr_response.attribute == routine_attributes["size"]:
                size_attr = SizeAttribute(br)
                self.size = size_attr.size * 3
            else:
                raise TypeError(f'Unknown attribute: {attr_response.attribute}')

    def add_code(self, code: bytes):
        self.code += code


class Task:
    def __init__(self, instance: int, response: bytes) -> None:
        self.programs_instances = []
        self.name = ""
        self.instance = instance
        self.type = "0"
        self.period = 0
        self.priority = 0
        self.watchdog = 0
        self._parse(response)

    def _parse(self, response: bytes):
        br = BinaryReader(response)
        attributes_response = AttributesResponse(br)
        for i in range(attributes_response.attribute_count):
            attr_response = Attribute(br)
            if attr_response.attribute == task_attributes["programs_instances"]:
                programs_instances_attr = ProgramInstancesAttribute(br)
                for program_instance in range(programs_instances_attr.instances_count):
                    self.programs_instances.append(int.from_bytes(br.read(bytesbe(4)), "little"))
            elif attr_response.attribute == task_attributes["name"]:
                name_attr = NameAttribute32(br)
                self.name = br.read(bytesbe(name_attr.size)).decode()
            elif attr_response.attribute == task_attributes["task_type"]:
                type_attr = uint16Attribute(br)
                self.type = task_priority.get(type_attr.value, str(type_attr.value))
            elif attr_response.attribute == task_attributes["priority"]:
                priority_attr = uint16Attribute(br)
                self.priority = priority_attr.value
            elif attr_response.attribute == task_attributes["period"]:
                period_attr = uint32Attribute(br)
                self.period = period_attr.value
            elif attr_response.attribute == task_attributes["watchdog"]:
                watchdog_attr = uint32Attribute(br)
                self.watchdog = watchdog_attr.value
            else:
                raise TypeError(f'Unknown attribute: {attr_response.attribute}')


class Tag:
    def __init__(self, response: bytes) -> None:
        self.name = ""
        self.type = 0
        self.address = 0
        self.symbol_address = 0
        self.control = 0
        self._parse(response)

    def _parse(self, response: bytes):
        br = BinaryReader(response)
        attributes_response = AttributesResponse(br)
        for i in range(attributes_response.attribute_count):
            attr_response = Attribute(br)
            if attr_response.attribute == tag_attributes["name"]:
                name_attr = NameAttribute(br)
                self.name = br.read(bytesbe(name_attr.size)).decode()
            elif attr_response.attribute == tag_attributes["type"]:
                type_attr = TypeAttribute(br)
                self.type = type_attr.type
            elif attr_response.attribute == tag_attributes["address"]:
                address_attr = AddressAttribute(br)
                self.address = address_attr.address
            elif attr_response.attribute == tag_attributes["symbol_address"]:
                symbol_address_attr = AddressAttribute(br)
                self.symbol_address = symbol_address_attr.address
            elif attr_response.attribute == tag_attributes["control"]:
                control_attr = ControlAttribute(br)
                self.control = control_attr.control
            else:
                raise TypeError(f'Unknown attribute: {attr_response.attribute}')


class ProgramTag:
    def __init__(self, response: dict) -> None:
        # dynamic attributes - currently using the pycomm3 program tag scheme
        for key in response.keys():
            setattr(self, key, response[key])


class Program:
    def __init__(self, name: str, instance: int, routines: list[Routine], tags: list[ProgramTag]):
        self.name = name
        self.instance = instance
        self.routines = routines
        self.tags = tags


class PortZero:
    def __init__(self, response: bytes) -> None:
        self.ports = []
        self.revision = 0
        self.max_instance = 0
        self.num_of_instances = 0
        self.entry_point = 0
        self._parse(response)

    def _parse(self, response: bytes):
        br = BinaryReader(response)
        port_zero = PortZeroAttributes(br)
        self.revision = port_zero.revision
        self.max_instance = port_zero.max_instance
        self.num_of_instances = port_zero.num_of_instances
        self.entry_point = port_zero.entry_point
        for i in range(port_zero.num_of_instances + 1):
            self.ports.append(PortInstance(br))


class ProjectName:
    def __init__(self, response: bytes) -> None:
        self.name = ""
        self._parse(response)

    def _parse(self, response: bytes):
        br = BinaryReader(response)
        project_name = ProjectNameResponse(br)
        self.name = br.read(bytesbe(project_name.size)).decode()


class ControllerKeyswitch:
    def __init__(self, response: bytes) -> None:
        self.state = "UNKNOWN"
        self._parse(response)

    def _parse(self, response: bytes):
        br = BinaryReader(response)
        keyswitch_state = KeyswitchResponse(br).state
        state_hi = keyswitch_state & 0xF0
        state_lo = keyswitch_state & 0x0F
        unk_state = "UNKNOWN"
        state = KEYSWITCH.get(state_hi, unk_state)["name"]
        ext_state = KEYSWITCH.get(state_hi, unk_state).get("extended", unk_state).get(state_lo, unk_state)
        if ext_state != unk_state:
            self.status = ext_state
        else:
            self.state = state


tag_attributes = {
    "name": 1,
    "type": 2,
    "address": 3,
    "symbol_address": 5,
    "control": 6
}

routine_attributes = {
    "name": 0x19,
    "type": 1,
    "address": 2,
    "size": 6
}

task_attributes = {
    "programs_instances": 1,
    "period": 2,
    "task_type": 5,
    "priority": 6,
    "watchdog": 0x0c,
    "name": 0x18
}

task_priority = {1: 'Event',
                 2: 'Periodic',
                 4: 'Continuous'}

# By Rockwell KB Article #28917
KEYSWITCH = {112: {"name": "PROG",
                   "extended": {32: "PROG", 33: "PROG", 48: "REMOTE PROG", 49: "REMOTE PROG"}
                   },
             96: {"name": "PROG",
                  "extended": {16: "RUN", 17: "RUN", 48: "REMOTE RUN", 49: "REMOTE RUN"}
                  }
             }
