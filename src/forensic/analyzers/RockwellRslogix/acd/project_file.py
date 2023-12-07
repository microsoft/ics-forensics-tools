import re
import gzip
from gzip import BadGzipFile
from typing import Union
from logging import Logger
from collections.abc import Sequence
from forensic.common.stream.stream import BinaryReader, uint32, bytesbe
from forensic.analyzers.RockwellRslogix.acd.dat_parser import DatHeader, RecordsHeader, Rung, Component, UnknownRecord, \
    RegionLink, Routine, component_types, Program, Controller


class ACDFile:
    def __init__(self, file_path: str, logger: Logger):
        self.logger = logger
        acd_file = open(file_path, "rb")
        self._acd_stream = BinaryReader(acd_file.read())
        acd_file.close()

        self._size = len(self._acd_stream)
        self._file_amount = 0
        self._version = 0
        self._first_record_offset = 0
        self.files = {}
        self.components = {}
        self.rungs = {}
        self.region_links = {}

        # self._verify_acd()
        self._read_footer()
        self._calculate_first_record_offset()
        self._unpack_to_files()

        self._initialize_components()
        self._initialize_rungs()
        self._initialize_region_links()

    def _read_footer(self):
        self._acd_stream.seek(-8, 2)
        self._file_amount = self._acd_stream.read(uint32)
        self._version = self._acd_stream.read(uint32)

    def _calculate_first_record_offset(self):
        record_size = 0x210
        file_footer_size = 8
        self._first_record_offset = self._size - file_footer_size - self._file_amount * record_size

    def _unpack_to_files(self):
        record_size = 0x210
        name_size = record_size - 8
        for i in range(self._file_amount):
            self._acd_stream.seek(self._first_record_offset + i * record_size)
            file_name = self._acd_stream.read(bytesbe(name_size)).decode("utf-16").strip("\x00").lower()
            file_size = self._acd_stream.read(uint32)
            file_offset = self._acd_stream.read(uint32)
            self._acd_stream.seek(file_offset)
            try:
                self.files[file_name] = BinaryReader(gzip.decompress(self._acd_stream.read(bytesbe(file_size))))
            except BadGzipFile:
                self._acd_stream.seek(file_offset)
                self.files[file_name] = BinaryReader(self._acd_stream.read(bytesbe(file_size)))

    def _initialize_components(self):
        comps_bs = self.files["comps.dat"]
        comps_bs.seek(0)
        dat_header = DatHeader(comps_bs)
        comps_bs.seek(dat_header.records_header_offset)
        records_header = RecordsHeader(comps_bs)
        comps_bs.seek(records_header.first_record_offset)
        comps_header = RecordsHeader(comps_bs)
        comps_header.unknown3 = comps_bs.read(bytesbe(comps_header.header_size - 0x16))
        start_of_record_offset = comps_bs.tell()
        while start_of_record_offset < dat_header.end_of_content_offset:
            try:
                sig = comps_bs.read(bytesbe(2))
                comps_bs.seek(-2, 1)
                if sig not in [b'\xfa\xfa', b'\xfd\xfd']:
                    unknown = UnknownRecord(comps_bs)
                    if unknown.struct_size > 0x6:
                        unknown.unknown = comps_bs.read(bytesbe(unknown.struct_size - 0x6))
                        start_of_record_offset = comps_bs.tell()
                    continue
                component = Component(comps_bs)
                component.variable_portion = comps_bs.read(bytesbe(component.variable_portion_size))
                if component.struct_size + start_of_record_offset > comps_bs.tell():
                    unknown = comps_bs.read(bytesbe(component.struct_size + start_of_record_offset - comps_bs.tell()))
                if self.components.get(component.uid) is not None:
                    print("duplicate")
                component.name = component.name.decode("utf-16").strip("\x00")
                self.components[component.uid] = component
                start_of_record_offset = comps_bs.tell()
            except Exception as e:
                print(e)

    def _initialize_rungs(self):
        rungs_bs = self.files["sbregion.dat"]
        rungs_bs.seek(0)
        dat_header = DatHeader(rungs_bs)
        rungs_bs.seek(dat_header.records_header_offset)
        records_header = RecordsHeader(rungs_bs)
        rungs_bs.seek(records_header.first_record_offset)
        rungs_header = RecordsHeader(rungs_bs)
        rungs_header.unknown3 = rungs_bs.read(bytesbe(rungs_header.header_size - 0x16))
        start_of_record_offset = rungs_bs.tell()
        while start_of_record_offset < dat_header.end_of_content_offset:
            rung = Rung(rungs_bs)
            rung.rung_content = rungs_bs.read(bytesbe(rung.rung_size))
            if rung.rung_content[1:4] == b"\xaa\x96\xaa":
                # Encrypted rung
                pass
            else:
                rung.rung_content = rung.rung_content.decode("utf-16").strip("\x00")
                rung.rung_content = self.rung_code_retrieve_references(rung.rung_content)
            self.rungs[rung.uid] = rung
            if start_of_record_offset + rung.struct_size > rungs_bs.tell():
                unknown = rungs_bs.read(bytesbe(rung.struct_size + start_of_record_offset - rungs_bs.tell()))
            start_of_record_offset = rungs_bs.tell()

    def _initialize_region_links(self):
        regnlink_bs = self.files["regnlink.dat"]
        regnlink_bs.seek(0)
        dat_header = DatHeader(regnlink_bs)
        regnlink_bs.seek(dat_header.records_header_offset)
        records_header = RecordsHeader(regnlink_bs)
        regnlink_bs.seek(records_header.first_record_offset)
        regnlink_header = RecordsHeader(regnlink_bs)
        regnlink_header.unknown3 = regnlink_bs.read(bytesbe(regnlink_header.header_size - 0x16))
        while regnlink_bs.tell() < dat_header.end_of_content_offset:
            region_link = RegionLink(regnlink_bs)
            self.region_links[region_link.uid] = region_link

    def component_get_parent_by_type(self, component: Component, component_type: Sequence,
                                     component_subtype: Sequence) -> Union[Component, None]:
        if component.parent_uid == 0:
            return ""
        parent = self.components[component.parent_uid]

        while not (parent.component_type in component_type and parent.component_subtype in component_subtype):
            parent = self.components[parent.parent_uid]

        return parent

    def rung_code_retrieve_references(self, rung_code: str) -> str:
        "Example: @bf82947a@ is a reference to a component with component uid 0x7a9482bf"
        for reverse_uid in re.findall(r"@\w{8}@", rung_code):
            uid = int.from_bytes(bytes.fromhex(reverse_uid[1:9])[::-1], "little")
            if uid in self.components:
                referenced_name = self.components[uid].name
            else:
                referenced_name = "??????"
            rung_code = rung_code.replace(reverse_uid, referenced_name)
        return rung_code

    def _get_routines(self) -> list[Routine]:
        routines = {}
        for rung_uid, region_link in self.region_links.items():
            # rung links have a the last byte in the flag different from 0
            if region_link.user_flag & 255 != 0:
                rung = self.rungs.get(rung_uid)
                if routines.get(region_link.parent_uid) is None:
                    rung_component = self.components.get(region_link.parent_uid)
                    if rung_component is not None:
                        routine_name = rung_component.name
                        # We currently don't have the definition of component subtypes, that is why we are using the number itself
                        program_comp = self.component_get_parent_by_type(rung_component,
                                                                         [component_types["ProgramModule"],
                                                                          component_types["AddOnInstruction"]], [1])
                        routine_uid = region_link.parent_uid
                        routines[routine_uid] = Routine(routine_uid, routine_name, program_comp.uid, rung)

                else:
                    routines[region_link.parent_uid].add_rung(rung)

        return list(routines.values())

    def _get_programs(self) -> list[Program]:
        programs = {}
        for routine in self._get_routines():
            program_uid = routine.program_uid
            if programs.get(program_uid) is None:
                program_comp = self.components.get(program_uid)
                if program_comp is not None:
                    program_name = program_comp.name
                    program = Program(program_uid, program_name)
                    programs[program_uid] = program
                else:
                    self.logger.error(f"Program component {program_uid} not found")
                    continue
            programs[program_uid].add_routine(routine)
        return list(programs.values())

    def get_controller(self) -> Controller:
        programs = self._get_programs()
        # There should be only one controller, so we take the parent of the first program
        first_program_comp = self.components.get(programs[0].uid)
        controller_comp = self.component_get_parent_by_type(first_program_comp, [component_types["Controller"]], [0])
        controller = Controller(controller_comp.name, programs)
        return controller
