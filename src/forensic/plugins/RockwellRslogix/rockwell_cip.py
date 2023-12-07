from forensic.plugins.RockwellRslogix.rockwell_structs import Routine, Tag, ProgramTag, tag_attributes, \
    routine_attributes, PortZero, ProjectName, ControllerKeyswitch, CipClasses, task_attributes, Task, ServiceCodes
from pycomm3 import LogixDriver


class RockwellCipClass:
    def __init__(self, cip_connection, route_path: str = "bp/0"):
        self._cip_connection = cip_connection
        self._cip_class = 0
        self._instances = []
        self._route_path = route_path

    def get_all_instances(self) -> list[int]:
        res = self._cip_connection.generic_message(service=ServiceCodes.GetAllInstances.value,
                                                   class_code=self._cip_class, instance=0,
                                                   connected=False, unconnected_send=True,
                                                   route_path=self._route_path).value
        for instance in range(0, len(res), 4):
            self._instances.append(int.from_bytes(res[instance:instance + 4], "little"))
        return self._instances

    @staticmethod
    def build_attribute_list(attributes: list) -> bytes:
        data = int.to_bytes(len(attributes), 2, "little")
        for attribute in attributes:
            data += int.to_bytes(attribute, 2, "little")
        return data

    def get_port_zero(self) -> PortZero:
        port_zero = None
        res = self._cip_connection.generic_message(service=ServiceCodes.GetAttributesAll.value,
                                                   class_code=CipClasses.PortObject.value,
                                                   instance=0, connected=False, unconnected_send=True,
                                                   route_path=self._route_path)
        if not res.error:
            port_zero = PortZero(res.value)
        return port_zero

    def get_project_name(self) -> str:
        project_name = ""
        res = self._cip_connection.generic_message(service=ServiceCodes.GetAttributesAll.value,
                                                   class_code=CipClasses.ProjectName.value,
                                                   instance=1, connected=False, unconnected_send=True,
                                                   route_path=self._route_path)
        if not res.error:
            project_name = ProjectName(res.value).name
        return project_name

    @staticmethod
    def get_keyswitch_state(status: bytes) -> str:
        keyswitch_state = "UNKNOWN"
        if status:
            keyswitch_state = ControllerKeyswitch(status).state
        return keyswitch_state


class TaskClass(RockwellCipClass):
    def __init__(self, cip_connection: LogixDriver, route_path: str = "bp/0"):
        super().__init__(cip_connection, route_path)
        self._cip_class = CipClasses.Task.value

    def _get_task(self, task_instance: int) -> Task:
        request_data = self.build_attribute_list([task_attributes["programs_instances"],
                                                  task_attributes["name"],
                                                  task_attributes["task_type"],
                                                  task_attributes["priority"],
                                                  task_attributes["period"],
                                                  task_attributes["watchdog"]])
        res = self._cip_connection.generic_message(class_code=self._cip_class,
                                                   service=ServiceCodes.GetAttributeList.value,
                                                   instance=task_instance, request_data=request_data, connected=False,
                                                   unconnected_send=True, route_path=self._route_path)
        task = Task(task_instance, res.value)
        return task

    def get_all_tasks(self) -> list[Task]:
        tasks = []
        for task_instance in self.get_all_instances():
            tasks.append(self._get_task(task_instance))
        return tasks


class ProgramClass(RockwellCipClass):
    def __init__(self, cip_connection: LogixDriver, route_path: str = "bp/0"):
        super().__init__(cip_connection, route_path)
        self._cip_class = CipClasses.Program.value

    def get_program_name(self, program_instance: int) -> str:
        program_name = ""
        request_data = self.build_attribute_list([0x1c])
        res = self._cip_connection.generic_message(class_code=self._cip_class,
                                                   service=ServiceCodes.GetAttributeList.value,
                                                   instance=program_instance, request_data=request_data,
                                                   connected=False, unconnected_send=True, route_path=self._route_path)
        program_name_size = int.from_bytes(res.value[6:10], "little")
        if program_name_size == len(res.value) - 10:
            program_name = (res.value[10:]).decode()
        return program_name

    @staticmethod
    def get_program_tags(program_name: str, all_user_tags: list[dict]) -> list[ProgramTag]:
        program_tags = []
        for tag in all_user_tags.keys():
            obj_type, _, data = tag.partition(":")
            if obj_type == "Program":
                tag_program_name, tag_name = data.split(".")
                if tag_program_name == program_name:
                    program_tags.append(ProgramTag(all_user_tags[tag]))
        return program_tags


class RoutineClass(RockwellCipClass):
    def __init__(self, cip_connection: LogixDriver, program_instance: int, route_path: str = "bp/0"):
        super().__init__(cip_connection, route_path)
        self._program_instance = program_instance
        self._cip_class = [CipClasses.Program.value, CipClasses.Routine.value]

    def _get_routine_code(self, routine_instance: int) -> bytes:
        request_data = bytes.fromhex("000000000000")
        instance = [self._program_instance, routine_instance]
        res = self._cip_connection.generic_message(class_code=self._cip_class, service=0x4c, instance=instance,
                                                   request_data=request_data, connected=False, unconnected_send=True,
                                                   route_path=self._route_path)
        return res.value[4:]

    def _get_all_instances(self) -> list[int]:
        message_instance = [self._program_instance, 0]
        res = self._cip_connection.generic_message(service=ServiceCodes.GetAllInstances.value,
                                                   class_code=self._cip_class, instance=message_instance,
                                                   connected=False, unconnected_send=True,
                                                   route_path=self._route_path).value
        for instance in range(0, len(res), 4):
            self._instances.append(int.from_bytes(res[instance:instance + 4], "little"))
        return self._instances

    def _get_routine(self, routine_instance: int) -> Routine:
        request_data = self.build_attribute_list([routine_attributes["name"],
                                                  routine_attributes["type"],
                                                  routine_attributes["address"],
                                                  routine_attributes["size"]])
        instance = [self._program_instance, routine_instance]
        res = self._cip_connection.generic_message(class_code=self._cip_class,
                                                   service=ServiceCodes.GetAttributeList.value,
                                                   instance=instance, request_data=request_data, connected=False,
                                                   unconnected_send=True, route_path=self._route_path)
        routine = Routine(self._program_instance, res.value)
        routine.add_code(self._get_routine_code(routine_instance))
        return routine

    def get_all_routines(self) -> list[Routine]:
        routines = []
        for routine_instance in self._get_all_instances():
            routines.append(self._get_routine(routine_instance))
        return routines


class TagClass(RockwellCipClass):
    def __init__(self, cip_connection: LogixDriver, program_instance: int, route_path: str = "bp/0"):
        super().__init__(cip_connection, route_path)
        self._program_instance = program_instance
        if program_instance == 0:
            self._cip_class = CipClasses.Tag.value
        else:
            self._cip_class = [CipClasses.Program.value, CipClasses.Tag.value]

    def get_tag(self, message_instance: list[int]) -> Tag:
        request_data = self.build_attribute_list([tag_attributes["name"],
                                                  tag_attributes["type"],
                                                  tag_attributes["address"],
                                                  tag_attributes["symbol_address"],
                                                  tag_attributes["control"]])
        res = self._cip_connection.generic_message(class_code=self._cip_class,
                                                   service=ServiceCodes.GetAttributeList.value,
                                                   instance=message_instance, request_data=request_data,
                                                   connected=False, unconnected_send=True, route_path=self._route_path)
        tag = Tag(res.value)
        return tag

    def get_all_instances(self) -> list[int]:
        if self._program_instance == 0:
            message_instance = [0]
        else:
            message_instance = [self._program_instance, 0]
        res = self._cip_connection.generic_message(service=ServiceCodes.GetAllInstances.value,
                                                   class_code=self._cip_class,
                                                   instance=message_instance,
                                                   connected=False, unconnected_send=True,
                                                   route_path=self._route_path).value
        for instance in range(0, len(res), 4):
            self._instances.append(int.from_bytes(res[instance:instance + 4], "little"))
        return self._instances

    def get_all_tags(self) -> list[Tag]:
        tags = []
        for tag_instance in self.get_all_instances():
            if self._program_instance == 0:
                message_instance = [tag_instance]
            else:
                message_instance = [self._program_instance, tag_instance]
            tags.append(self.get_tag(message_instance))
        return tags
