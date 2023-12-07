from pycomm3 import LogixDriver
from forensic.plugins.RockwellRslogix.rockwell_cip import *
from forensic.plugins.RockwellRslogix.rockwell_structs import *


class LogixConn:
    def __init__(self, logger, path: str, timeout: float = 5.0) -> None:
        self.conn = LogixDriver(path)
        self.conn.socket_timeout = timeout
        self.modules = []
        self.all_user_tags = []
        self._rockwell_cip_class = RockwellCipClass(self.conn)

    def get_modules(self) -> list[int]:
        modules = []
        port_zero = self._rockwell_cip_class.get_port_zero()
        if port_zero:
            for port in port_zero.ports:
                modules.append(port.port_number)
        else:
            modules.append(0)
        return modules

    def get_all_user_tags(self) -> list[dict]:
        self.conn.get_tag_list(program="*")
        return self.conn.tags_json

    def __enter__(self):
        self.conn.open()
        self.modules = self.get_modules()
        self.all_user_tags = self.get_all_user_tags()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()


class ModuleComm:
    def __init__(self, logger, conn: LogixDriver, module: int, all_user_tags) -> None:
        self._conn = conn
        self._module = module
        self._all_user_tags = all_user_tags
        self._route_path = f"bp/{module}"
        self._logger = logger
        self._rockwell_cip_class = RockwellCipClass(self._conn, self._route_path)

    def dump_module(self):
        res = None
        try:
            res = {"Identity": self._conn.get_module_info(self._module)}
            self._logger.info(f"Module in slot {self._module} is reachable")

            res['Identity']['project_name'] = self._rockwell_cip_class.get_project_name()
            res['Identity']['keyswitch'] = self._rockwell_cip_class.get_keyswitch_state(res["Identity"]["status"])

            tasks = self.upload_all_tasks()
            if tasks:
                res['tasks'] = tasks

            programs = self.upload_all_programs(self._all_user_tags)
            if programs:
                res['programs'] = programs

            tags = self.upload_device_tags()
            if tags:
                res['tags'] = tags
        except Exception as e:
            self._logger.info(f"Slot {self._module} is unreachable")
        return res

    def upload_all_tasks(self):
        task_class = TaskClass(self._conn, self._route_path)
        return task_class.get_all_tasks()

    def upload_all_programs(self, all_user_tags) -> list[Program]:
        programs = []
        program_class = ProgramClass(self._conn, self._route_path)
        program_instances = program_class.get_all_instances()
        for program_instance in program_instances:
            program_name = program_class.get_program_name(program_instance)
            tags = program_class.get_program_tags(program_name, all_user_tags)
            routine_class = RoutineClass(self._conn, program_instance, self._route_path)
            routines = routine_class.get_all_routines()
            programs.append(Program(program_name, program_instance, routines, tags))

        return programs

    def upload_device_tags(self) -> list[Tag]:
        tag_class = TagClass(self._conn, 0, self._route_path)
        return tag_class.get_all_tags()


class RockwellError(Exception):
    pass
