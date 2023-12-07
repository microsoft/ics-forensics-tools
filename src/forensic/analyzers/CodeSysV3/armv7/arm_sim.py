from collections import defaultdict

import struct
import capstone
import networkx as nx
from typing import Any, Tuple

from forensic.common.stream.stream import *


def null_func():
    pass


mybreakpoint = null_func  # breakpoint()


class SparseBytesIO:
    def __init__(self, data: bytes = b''):
        self._data = {}
        self._pointer = 0
        self._size = 0
        self.write(data)

    def seek(self, offset, whence=0):
        if whence == 0:
            self._pointer = offset
        elif whence == 1:
            self._pointer += offset
        elif whence == 2:
            self._pointer = self._size + offset

    def tell(self):
        return self._pointer

    def write(self, data):
        for i, b in enumerate(data):
            self._data[self._pointer + i] = b
        self._pointer += len(data)
        self._size = max(self._size, self._pointer)

    def read(self, num_bytes=-1):
        if num_bytes == -1:
            num_bytes = self._size - self._pointer
        bytes = bytearray(num_bytes)
        for i in range(num_bytes):
            bytes[i] = self._data.get(self._pointer + i, 0)
        self._pointer += num_bytes
        return bytes

    def getvalue(self):
        return bytes(self._data.get(i, 0) for i in range(self._size))


class MemoryStream(BinaryReader, BinaryWriter):
    def __init__(self, data: bytes = b'', endianness: Endianness = Endianness.LITTLE) -> None:
        super().__init__(endianness)
        self._base_stream = SparseBytesIO(data)

    def read(self, basic_type: BasicType, dt_name=None, enable_check=True) -> Any:
        return super().read(basic_type, dt_name, False)


class ArmMachineSimulator:
    def __init__(self, memory_file: bytes, is_thumb=False):
        self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.memory = MemoryStream(memory_file)
        self._raw_memory = memory_file
        self.registers = defaultdict(int)
        self.is_thumb = is_thumb
        self._functions = {}
        self._destination_addr = 0xFFFFFFFD
        self._memory_size = len(memory_file)
        self.function_storage = {}
        self._patched_functions = {}

    def _init_run(self):
        self.registers = defaultdict(int)
        self.registers['sp'] = 0xF0000000

    def write_mem(self, address, basic_type, value):
        self.memory.seek(address)
        self.memory.write(basic_type, value)

    def write_mem_struct(self, address, basic_type, value):
        self.memory.seek(address)
        self.memory.write_struct(basic_type, value)

    def read_mem(self, address, basic_type) -> Any:
        self.memory.seek(address)
        return self.memory.read(basic_type)

    def read_struct(self, address, basic_type) -> Any:
        self.memory.seek(address)
        return self.memory.read_struct(basic_type)

    def push_stack(self, val: int):
        self.memory.seek(self.registers['sp'] - 4)
        self.memory.write(uint32le, val)
        self.registers['sp'] -= 4

    def pop_stack(self):
        self.memory.seek(self.registers['sp'])
        read_val = self.memory.read(uint32)
        self.registers['sp'] += 4

        return read_val

    def move_stack(self, offset: int):
        self.registers['sp'] += offset

    def get_reg(self, reg, is_used_for_mem=False):
        if type(reg) is int:
            reg = self.md.reg_name(reg)

        res = self.registers[reg]

        if is_used_for_mem and reg == 'pc':
            res += 8 if not self.is_thumb else 4

        return res

    def set_reg(self, reg, val):
        if type(reg) is int:
            reg = self.md.reg_name(reg)

        self.registers[reg] = val

    def format_regs(self):
        return str(dict((k, hex(v)) for k, v in self.registers.items()))

    def _is_inst(self, inst, val):
        return f'{inst.mnemonic} {inst.op_str}' == val

    def add_patch_function(self, symbol, address, function):
        self._patched_functions[self._destination_addr] = {'func_name': symbol,
                                                           'address_to_patch': address,
                                                           'handler': function}
        self.write_mem(address, uint32le, self._destination_addr)
        self._destination_addr -= 1

    def dump_memory(self):
        return self.read_mem(0, bytesbe(self._memory_size))

    # Iterate over the function to find it bounds, going through all the jumps
    def iterate_no_emulate(self, start_ea: int):
        prolog = 'push {sl, lr}'
        epilog = 'pop {sl, pc}'
        s_visited_addresses = set()
        address_to_visit = [start_ea]

        while len(address_to_visit) > 0:
            curr_ea = address_to_visit.pop(0)

            for inst in self.md.disasm(self._raw_memory[curr_ea:], curr_ea):
                if inst.address in s_visited_addresses:
                    break
                s_visited_addresses.add(inst.address)
                # Is the start of the function has prolog
                if inst.address == start_ea and not self._is_inst(inst, prolog):
                    break

                # End of function
                if self._is_inst(inst, epilog):
                    yield inst
                    break

                if capstone.arm.ARM_GRP_JUMP in inst.groups and inst.operands[0].type == capstone.arm.ARM_OP_IMM:
                    address_to_visit.append(inst.operands[0].imm)

                    # That means we don't branch twice
                    if inst.mnemonic in ['b', 'bl', 'bx', 'blx']:
                        yield inst
                        break

                yield inst

    def xref_graph(self, all_code, symbols, start_ea):
        g = nx.DiGraph()
        s_visited_addresses = set()
        address_to_visit = [start_ea]

        while len(address_to_visit) > 0:
            curr_ea = address_to_visit.pop(0)
            for inst in self.iterate_no_emulate(curr_ea):
                if inst.address in s_visited_addresses:
                    break
                s_visited_addresses.add(inst.address)

                if inst.mnemonic == 'ldr':
                    if inst.operands[0].type == capstone.arm.ARM_OP_REG and \
                            inst.operands[1].type == capstone.arm.ARM_OP_MEM and \
                            inst.operands[1].mem.base == capstone.arm.ARM_REG_PC:
                        address = (inst.operands[
                                       1].mem.disp + inst.address + 8 if not self.is_thumb else 4) & 0xFFFFFFFF
                        jump_address = self.read_mem(address, uint32le)
                        jump_target = self.read_mem(jump_address, uint32le)

                        if jump_target in all_code:
                            if jump_target not in s_visited_addresses:
                                address_to_visit.append(jump_target)

                            g.add_edge(f'{hex(curr_ea)} {symbols.get(curr_ea, "")}'.strip(),
                                       f'{hex(jump_target)} {symbols.get(jump_target, "")}'.strip())
                        elif jump_address in symbols:
                            g.add_edge(f'{hex(curr_ea)} {symbols.get(curr_ea, "")}'.strip(),
                                       f'{symbols.get(jump_address, "")}'.strip())

        return g

    def simulate_function(self, start_ea: int):
        end_addr = 0xFFFFFFFE
        self._init_run()
        self.set_reg('lr', end_addr)
        self.set_reg('pc', start_ea)

        while self.get_reg('pc') != end_addr:
            if self.get_reg('pc') in self._patched_functions:
                self._patched_functions[self.get_reg('pc')]['handler'](self)
                self.set_reg('pc', self.get_reg('lr'))
                continue

            curr_pc = self.get_reg('pc')
            code_to_disasm = self.read_mem(curr_pc, bytesbe(4))
            inst = next(self.md.disasm(code_to_disasm, curr_pc, 1))

            # print(f'{hex(inst.address)} {inst.mnemonic} {inst.op_str}')

            if inst.address in []:
                mybreakpoint()

            if inst.mnemonic.startswith('ldr'):
                if inst.operands[0].type == capstone.arm.ARM_OP_REG and inst.operands[
                    1].type == capstone.arm.ARM_OP_MEM:
                    source_address = self.get_reg(inst.operands[1].mem.base, True)

                    if inst.operands[1].mem.index != 0:
                        source_address += self.get_reg(inst.operands[1].mem.index, True)

                    source_address += inst.operands[1].mem.disp
                    source_address &= 0xFFFFFFFF

                    if inst.mnemonic == 'ldr':
                        dtype = uint32le
                    elif inst.mnemonic == 'ldrb':
                        dtype = ubyte
                    elif inst.mnemonic == 'ldrh':
                        dtype = uint16le
                    else:
                        mybreakpoint()

                    # address = (self.get_reg(inst.operands[1].reg, True) + inst.operands[1].mem.disp) & 0xFFFFFFFF
                    target_reg = inst.operands[0].reg
                    self.set_reg(target_reg, self.read_mem(source_address, dtype))
                    if inst.writeback:
                        self.move_stack(-4)
                else:
                    mybreakpoint()
            elif inst.mnemonic == 'push':
                for op in reversed(inst.operands):
                    if op.type == capstone.arm.ARM_OP_REG:
                        reg = self.md.reg_name(op.reg)
                        self.push_stack(self.registers[reg])
                    else:
                        mybreakpoint()
            elif inst.mnemonic == 'pop':
                for op in inst.operands:
                    if op.type == capstone.arm.ARM_OP_REG:
                        self.set_reg(op.reg, self.pop_stack())
                    else:
                        mybreakpoint()
            elif inst.mnemonic == 'sub':
                if inst.operands[0].type == capstone.arm.ARM_OP_REG and inst.operands[
                    1].type == capstone.arm.ARM_OP_REG and \
                        inst.operands[2].type == capstone.arm.ARM_OP_IMM:
                    target_reg = self.md.reg_name(inst.operands[0].reg)
                    source_reg = self.md.reg_name(inst.operands[1].reg)
                    self.registers[target_reg] = self.registers[source_reg] - inst.operands[2].imm
                else:
                    mybreakpoint()
            elif inst.mnemonic == 'mov':
                if inst.operands[0].type == capstone.arm.ARM_OP_REG:
                    if inst.operands[1].type == capstone.arm.ARM_OP_REG:
                        val = self.get_reg(inst.operands[1].reg, True)
                    elif inst.operands[1].type == capstone.arm.ARM_OP_IMM:
                        val = inst.operands[1].imm
                    else:
                        mybreakpoint()

                    self.set_reg(inst.operands[0].reg, val)
                else:
                    mybreakpoint()
            elif inst.mnemonic.startswith('str'):
                if inst.operands[0].type == capstone.arm.ARM_OP_REG and inst.operands[
                    1].type == capstone.arm.ARM_OP_MEM:
                    source_reg = inst.operands[0].reg
                    target_address = self.get_reg(inst.operands[1].mem.base, True)

                    if inst.operands[1].mem.index != 0:
                        target_address += self.get_reg(inst.operands[1].mem.index, True)

                    target_address += inst.operands[1].mem.disp
                    target_address &= 0xFFFFFFFF

                    if inst.mnemonic == 'str':
                        dtype = uint32le
                    elif inst.mnemonic == 'strb':
                        dtype = ubyte
                    elif inst.mnemonic == 'strh':
                        dtype = uint16le
                    else:
                        mybreakpoint()
                    self.write_mem(target_address, dtype, self.get_reg(source_reg))

                    if inst.writeback:
                        self.move_stack(-4)
                else:
                    mybreakpoint()
            elif inst.mnemonic == 'add':
                if len(inst.operands) == 3 and inst.operands[0].type == capstone.arm.ARM_OP_REG and \
                        inst.operands[1].type == capstone.arm.ARM_OP_REG:
                    target_reg = inst.operands[0].reg
                    middle_reg_val = self.get_reg(inst.operands[1].reg)

                    if inst.operands[2].type == capstone.arm.ARM_OP_REG:
                        source_val = self.get_reg(inst.operands[2].reg)
                    elif inst.operands[2].type == capstone.arm.ARM_OP_IMM:
                        source_val = inst.operands[2].imm
                    else:
                        mybreakpoint()

                    self.set_reg(target_reg, (middle_reg_val + source_val) & 0xFFFFFFFF)
                else:
                    mybreakpoint()
            elif inst.mnemonic.startswith('and'):
                if inst.mnemonic == 'and' or (inst.mnemonic == 'andvs' and self.get_reg('v_flag') == 1):
                    if len(inst.operands) == 3 and inst.operands[0].type == capstone.arm.ARM_OP_REG and \
                            inst.operands[1].type == capstone.arm.ARM_OP_REG and \
                            inst.operands[2].type == capstone.arm.ARM_OP_REG:
                        target_reg = inst.operands[0].reg
                        middle_reg = inst.operands[1].reg
                        source_reg = inst.operands[2].reg
                        self.set_reg(target_reg, (self.get_reg(middle_reg) & self.get_reg(source_reg)) & 0xFFFFFFFF)
                    else:
                        mybreakpoint()
            elif inst.mnemonic == 'b':
                self.set_reg('pc', inst.operands[0].imm)
            elif inst.mnemonic == 'bl':
                self.set_reg('lr', self.get_reg('pc') + 4)
                self.set_reg('pc', inst.operands[0].imm)
            elif inst.mnemonic == 'cmp':
                if inst.operands[0].type == capstone.arm.ARM_OP_REG and inst.operands[
                    1].type == capstone.arm.ARM_OP_REG:
                    left_reg_val = self.get_reg(inst.operands[0].reg)
                    right_reg_val = self.get_reg(inst.operands[1].reg)
                    self.set_reg('n_flag', 1 if left_reg_val - right_reg_val < 0 else 0)
                    self.set_reg('z_flag', 1 if left_reg_val - right_reg_val == 0 else 0)
                    self.set_reg('c_flag', 1 if right_reg_val > left_reg_val else 0)
                    self.set_reg('v_flag', 1 if left_reg_val > 0x80000000 and (
                            (left_reg_val - right_reg_val) & 0xFFFFFFFF) <= 0x7fffffff else 0)
                    # for adds left_reg_val + right_reg_val >= 0x7FFFFFFF
            elif inst.mnemonic == 'bgt':
                if self.get_reg('n_flag') == self.get_reg('v_flag') and self.get_reg('z_flag') == 0:
                    self.set_reg('pc', inst.operands[0].imm)
            elif inst.mnemonic == 'mul':
                target_reg = inst.operands[0].reg
                middle_reg_val = self.get_reg(inst.operands[1].reg)

                if inst.operands[2].type == capstone.arm.ARM_OP_REG:
                    source_val = self.get_reg(inst.operands[2].reg)
                elif inst.operands[2].type == capstone.arm.ARM_OP_IMM:
                    source_val = inst.operands[2].imm
                else:
                    mybreakpoint()

                self.set_reg(target_reg, (middle_reg_val * source_val) & 0xFFFFFFFF)
            else:
                mybreakpoint()

            # print(self.format_regs())

            if self.read_mem(0x2b38, uint32le) == 0x4:
                mybreakpoint()

            # Check whether the PC register was modified during runtime
            if curr_pc == self.get_reg('pc'):
                self.set_reg('pc', inst.address + 4)
