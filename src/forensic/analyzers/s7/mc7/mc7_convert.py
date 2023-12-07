import binascii
from forensic.common.stream.stream import BinaryReader, StreamNotEnoughData, uint16be, ubyte, char, bytesbe, uint32be


ops = {'00 00': 'NOP 0', '01 00': 'INVI', '05 00': 'BEC', '09 00': 'NEGI', '21 20': '>I', '21 40': '>=I',
       '21 60': '<>I',
       '21 80': '==I', '21 A0': '<I', '21 C0': '<=I', '31 20': '>R', '31 40': '>=R', '31 60': '<>R', '31 80': '==R',
       '31 A0': '<R', '31 C0': '<=R', '39 20': '>D', '39 40': '>=D', '39 60': '<>D', '39 80': '==D', '39 A0': '<D',
       '39 C0': '<=D', '41 00': 'AW', '49 00': 'OW', '51 00': 'XOW', '59 00': '-I', '60 00': '/I', '60 01': 'MOD',
       '60 02': 'ABS', '60 03': '/R', '60 04': '*I', '60 06': 'NEGR', '60 07': '*R', '60 08': 'ENT', '60 09': '-D',
       '60 0A': '*D', '60 0B': '-R', '60 0D': '+D', '60 0E': '/D', '60 0F': '+R', '60 10': 'SIN', '60 11': 'COS',
       '60 12': 'TAN', '60 13': 'LN', '60 14': 'SQRT', '60 18': 'ASIN', '60 19': 'ACOS', '60 1A': 'ATAN',
       '60 1B': 'EXP', '60 1C': 'SQR', '65 00': 'BE', '65 01': 'BEU', '68 06': 'DTR', '68 07': 'NEGD', '68 08': 'ITB',
       '68 0A': 'DTB', '68 0C': 'BTI', '68 0E': 'BTD', '68 0D': 'INVD', '68 12': 'SLW', '68 13': 'SLD', '68 17': 'RLD',
       '68 18': 'RLDA', '68 1A': 'CAW', '68 1B': 'CAD', '68 1C': 'CLR', '68 1D': 'SET', '68 1E': 'ITD', '68 22': 'SRW',
       '68 23': 'SRD', '68 24': 'SSI', '68 25': 'SSD', '68 27': 'RRD', '68 28': 'RRDA', '68 2C': 'SAVE', '68 2D': 'NOT',
       '68 2E': 'PUSH', '68 37': 'AD', '68 3A': 'MCRA', '68 3B': 'MCRD', '68 3C': 'MCR(', '68 3D': ')MCR',
       '68 3E': 'POP',
       '68 47': 'OD', '68 4E': 'LEAVE', '68 57': 'XOD', '68 5C': 'RND', '68 5D': 'RND-', '68 5E': 'RND+',
       '68 5F': 'TRUNC',
       '70 02': 'TAK', '70 06': 'L STW', '70 07': 'T STW', '79 00': '+I', 'BA 00': 'A(', 'BB 00': 'O(', 'BF 00': ')',
       'FB 00': 'O', 'FB 3C': 'L DBLG', 'FB 3D': 'L DILG', 'FB 4C': 'L DBNO', 'FB 4D': 'L DINO', 'FB 7C': 'CDB',
       'FE 01': 'LAR1 AR2', 'FE 04': 'LAR1', 'FE 05': 'TAR1', 'FE 06': '0', 'FE 08': 'CAR', 'FE 09': 'TAR1 AR2',
       'FE 0C': 'LAR2', 'FE 0D': 'TAR2', 'FE 0E': '0', 'FF 00': 'A OS', 'FF 01': 'AN OS', 'FF 02': 'O OS',
       'FF 03': 'ON OS', 'FF 04': 'X OS', 'FF 05': 'XN OS', 'FF 10': 'A OV', 'FF 11': 'AN OV', 'FF 12': 'O OV',
       'FF 13': 'ON OV', 'FF 14': 'X OV', 'FF 15': 'XN OV', 'FF 20': 'A >0', 'FF 21': 'AN >0', 'FF 22': 'O >0',
       'FF 23': 'ON >0', 'FF 24': 'X >0', 'FF 25': 'XN >0', 'FF 40': 'A <0', 'FF 41': 'AN <0', 'FF 42': 'O <0',
       'FF 43': 'ON <0', 'FF 44': 'X <0', 'FF 45': 'XN <0', 'FF 50': 'A UO', 'FF 51': 'AN UO', 'FF 52': 'O UO',
       'FF 53': 'ON UO', 'FF 54': 'X UO', 'FF 55': 'XN UO', 'FF 60': 'A <>0', 'FF 61': 'AN <>0', 'FF 62': 'O <>0',
       'FF 63': 'ON <>0', 'FF 64': 'X <>0', 'FF 65': 'XN <>0', 'FF 80': 'A ==0', 'FF 81': 'AN ==0', 'FF 82': 'O ==0',
       'FF 83': 'ON ==0', 'FF 84': 'X ==0', 'FF 85': 'XN ==0', 'FF A0': 'A >=0', 'FF A1': 'AN >=0', 'FF A2': 'O >=0',
       'FF A3': 'ON >=0', 'FF A4': 'X >=0', 'FF A5': 'XN >=0', 'FF C0': 'A <=0', 'FF C1': 'AN <=0', 'FF C2': 'O <=0',
       'FF C3': 'ON <=0', 'FF C4': 'X <=0', 'FF C5': 'XN <=0', 'FF E0': 'A BR', 'FF E1': 'AN BR', 'FF E2': 'O BR',
       'FF E3': 'ON BR', 'FF E4': 'X BR', 'FF E5': 'XN BR', 'FF F1': 'AN(', 'FF F3': 'ON(', 'FF F4': 'X(',
       'FF F5': 'XN(', 'FF FF': 'NOP 1'}

def twos_complement_hex(hexval):
    bits = 16
    val = int(hexval, bits)
    if val & (1 << (bits - 1)):
        val -= 1 << bits
    return val


def mc7_to_awl(data):
    commands = []
    if data:
        raw_data = binascii.unhexlify(data)
        br = BinaryReader(raw_data)
        while True:
            try:
                msg = ''
                op1 = br.read(char)
                if not op1:
                    # print('error! no data')
                    break
                op1_str = op1.hex().upper()
                op1_int = int(op1.hex(), 16)
                op2 = br.read(char)
                if not op2:
                    # print('error! no data')
                    break
                op2_str = op2.hex().upper()
                op2_int = int(op2.hex(), 16)
                op_value = f'{op1_str} {op2_str}'
                if op_value in ops:
                    commands.append(ops[op_value])
                else:
                    commands_16 = {0x29: 'SLD', 0x61: 'SLW', 0x68: 'SSI', 0x69: 'SRW', 0x71: 'SSD',
                                   0x74: 'RRD', 0xFE: 'SRD'}

                    commands_255 = {0x02: f'L T {op2_int}', 0x04: f'FR T {op2_int}', 0x0A: f'L MB {op2_int}',
                                    0x0B: f'T MB {op2_int}', 0x0C: f'LC T {op2_int}', 0x10: f'BLD {op2_int}',
                                    0x11: f'DEC {op2_int}', 0x12: f'L MW {op2_int}', 0x13: f'T MW {op2_int}',
                                    # 11 might be inc, 19 might be dec
                                    0x14: f'SF T {op2_int}', 0x19: f'INC {op2_int}', 0x1A: f'L MD {op2_int}',
                                    0x1B: f'T MD {op2_int}', 0x1C: f'SE T {op2_int}', 0x1D: f'CC FC {op2_int}',
                                    0x20: f'OPN DB{op2_int}', 0x24: f'SD T {op2_int}', 0x28: f'L B#16#{op2_int}',
                                    0x2C: f'SS T {op2_int}', 0x34: f'SP T {op2_int}', 0x3C: f'R T {op2_int}',
                                    0x3D: f'UC FC {op2_int}', 0x42: f'L C {op2_int}', 0x44: f'FR C {op2_int}',
                                    0x4C: f'LC C {op2_int}', 0x54: f'CD C {op2_int}', 0x55: f'CC FB {op2_int}',
                                    0x5C: f'S {op2_int}', 0x6C: f'CU C {op2_int}', 0x75: f'UC FB {op2_int}',
                                    0x7C: f'R {op2_int}', 0x80: f'A M {op2_int}.0', 0x81: f'A M {op2_int}.1',
                                    0x82: f'A M {op2_int}.2', 0x83: f'A M {op2_int}.3', 0x84: f'A M {op2_int}.4',
                                    0x85: f'A M {op2_int}.5', 0x86: f'A M {op2_int}.6', 0x87: f'A M {op2_int}.7',
                                    0x88: f'O M {op2_int}.0', 0x89: f'O M {op2_int}.1', 0x8A: f'O M {op2_int}.2',
                                    0x8B: f'O M {op2_int}.3', 0x8C: f'O M {op2_int}.4', 0x8D: f'O M {op2_int}.5',
                                    0x8E: f'O M {op2_int}.6', 0x8F: f'O M {op2_int}.7', 0x90: f'S M {op2_int}.0',
                                    0x91: f'S M {op2_int}.1', 0x92: f'S M {op2_int}.2', 0x93: f'S M {op2_int}.3',
                                    0x94: f'S M {op2_int}.4', 0x95: f'S M {op2_int}.5', 0x96: f'S M {op2_int}.6',
                                    0x97: f'S M {op2_int}.7', 0x98: f'= M {op2_int}.0', 0x99: f'= M {op2_int}.1',
                                    0x9A: f'= M {op2_int}.2', 0x9B: f'= M {op2_int}.3', 0x9C: f'= M {op2_int}.4',
                                    0x9D: f'= M {op2_int}.5', 0x9E: f'= M {op2_int}.6', 0x9F: f'= M {op2_int}.7',
                                    0xA0: f'AN M {op2_int}.0', 0xA1: f'AN M {op2_int}.1', 0xA2: f'AN M {op2_int}.2',
                                    0xA3: f'AN M {op2_int}.3', 0xA4: f'AN M {op2_int}.4', 0xA5: f'AN M {op2_int}.5',
                                    0xA6: f'AN M {op2_int}.6', 0xA7: f'AN M {op2_int}.7', 0xA8: f'ON M {op2_int}.0',
                                    0xA9: f'ON M {op2_int}.1', 0xAA: f'ON M {op2_int}.2', 0xAB: f'ON M {op2_int}.3',
                                    0xAC: f'ON M {op2_int}.4', 0xAD: f'ON M {op2_int}.5', 0xAE: f'ON M {op2_int}.6',
                                    0xAF: f'ON M {op2_int}.7', 0xB0: f'R M {op2_int}.0', 0xB1: f'R M {op2_int}.1',
                                    0xB2: f'R M {op2_int}.2', 0xB3: f'R M {op2_int}.3', 0xB4: f'R M {op2_int}.4',
                                    0xB5: f'R M {op2_int}.5', 0xB6: f'R M {op2_int}.6', 0xB7: f'R M {op2_int}.7',
                                    0xB8: f'A C {op2_int}', 0xB9: f'O C {op2_int}', 0xBC: f'AN {op2_int}',
                                    0xBD: f'ON {op2_int}', 0xF8: f'A T {op2_int}', 0xF9: f'O T {op2_int}',
                                    0xFC: f'AN T {op2_int}', 0xFD: f'ON T {op2_int}'}
                    if op1_int in commands_16:
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        if op1_int == 0x68 and point_v == 1:
                            commands.append(f'{commands_16[op1_int]} {op2_v}')
                        elif op2_v == 0:
                            commands.append(f'{commands_16[op1_int]} {point_v}')
                        elif op2_v == 12 and op1_int == 0xFE:
                            commands.append(f'{commands_16[op1_int]} {point_v}')
                    elif op1_int in commands_255 and op2_int <= 255:
                        commands.append(commands_255[op1_int])
                        if op1_int == 0x3D:
                            br.read(bytesbe(3))
                            param_length = int((br.read(ubyte) / 2) - 1)
                            for x in range(param_length):
                                param_data = br.read(bytesbe(4))
                                pv = {
                                    0x80: f'P#PE ',
                                    0x81: f'P#E  ',
                                    0x82: f'P#A  ',
                                    0x83: f'P#M  ',
                                    0x84: f'P#DBX ',
                                    0x85: f'P#DIX ',
                                    0x86: f'P#L ',
                                    0x87: f'P#V '
                                }
                                if param_data[0] in pv:
                                    param_value = (param_data[2] * 0x100 + param_data[3]) >> 3
                                    param_pv = (param_data[3] & 0x07)
                                    str_param_p = f'{param_value}.{param_pv}'
                                    commands.append(f'{pv[param_data[0]]}{str_param_p}')
                                else:
                                    param_value = (param_data[0] * 0x100 + param_data[1]);
                                    commands.append(f'P#{(param_value >> 3)}.{(param_value & 0x7)}')
                    elif op1_int == 0:
                        value = br.read(uint16be)
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_value_dict = {1: f"A I {value}.{point_v}",
                                          2: f"A Q {value}.{point_v}",
                                          3: f"A M {value}.{point_v}",
                                          4: f"A DBX {value}.{point_v}",
                                          5: f"A DIX {value}.{point_v}",
                                          6: f"A L {value}.{point_v}",
                                          9: f"AN I {value}.{point_v}",
                                          0xA: f"AN Q {value}.{point_v}",
                                          0xB: f"AN M {value}.{point_v}",
                                          0xC: f"AN DBX {value}.{point_v}",
                                          0xD: f"AN DIX {value}.{point_v}",
                                          0xE: f"AN L {value}.{point_v}",
                                          }
                        if (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v <= 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v <= 7):
                            msg = '_!!ERR_out_of_allowed_range!!'
                        elif (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v > 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v > 7):
                            msg = '_!!TODO_BLD_logic!!'
                        if op2_v in op2_value_dict:
                            commands.append(f'{op2_value_dict[op2_v]}{msg}')
                    elif op1_int == 1:
                        value = br.read(uint16be)
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_value_dict = {1: f"O I {value}.{point_v}",
                                          2: f"O Q {value}.{point_v}",
                                          3: f"O M {value}.{point_v}",
                                          4: f"O DBX {value}.{point_v}",
                                          5: f"O DIX {value}.{point_v}",
                                          6: f"O L {value}.{point_v}",
                                          9: f"ON I {value}.{point_v}",
                                          0xA: f"ON Q {value}.{point_v}",
                                          0xB: f"ON M {value}.{point_v}",
                                          0xC: f"ON DBX {value}.{point_v}",
                                          0xD: f"ON DIX {value}.{point_v}",
                                          0xE: f"ON L {value}.{point_v}",
                                          }
                        if (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v <= 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v <= 7):
                             msg = '_!!ERR_out_of_allowed_range!!'
                        elif (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v > 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v > 7):
                            msg = '_!!TODO_BLD_logic!!'
                        if op2_v in op2_value_dict:
                            commands.append(f'{op2_value_dict[op2_v]}{msg}')
                    elif op1_int == 5:
                        value = br.read(uint16be)
                        point_v = int(op2_str[1],16)
                        op2_v = int(op2_str[0],16)
                        op2_value_dict = {1: f"X I {value}.{point_v}",
                                          2: f"X Q {value}.{point_v}",
                                          3: f"X M {value}.{point_v}",
                                          4: f"X DBX {value}.{point_v}",
                                          5: f"X DIX {value}.{point_v}",
                                          6: f"X L {value}.{point_v}",
                                          9: f"XN I {value}.{point_v}",
                                          0xA: f"XN Q {value}.{point_v}",
                                          0xB: f"XN M {value}.{point_v}",
                                          0xC: f"XN DBX {value}.{point_v}",
                                          0xD: f"XN DI {value}.{point_v}",
                                          0xE: f"XN L {value}.{point_v}",
                                          }
                        if (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v <= 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v <= 7):
                             msg = '_!!ERR_out_of_allowed_range!!'
                        elif (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v > 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v > 7):
                            msg = '_!!TODO_BLD_logic!!'
                        if op2_v in op2_value_dict:
                            commands.append(f'{op2_value_dict[op2_v]}{msg}')
                    elif op1_int == 9:
                        value = br.read(uint16be)
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_value_dict = {1: f"S I {value}.{point_v}",
                                          2: f"S Q {value}.{point_v}",
                                          3: f"S M {value}.{point_v}",
                                          4: f"S DBX {value}.{point_v}",
                                          5: f"S DIX {value}.{point_v}",
                                          6: f"S L {value}.{point_v}",
                                          9: f"R I {value}.{point_v}",
                                          0xA: f"R Q {value}.{point_v}",
                                          0xB: f"R M {value}.{point_v}",
                                          0xC: f"R DBX {value}.{point_v}",
                                          0xD: f"R DI {value}.{point_v}",
                                          0xE: f"R L {value}.{point_v}",
                                          }
                        if (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v <= 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v <= 7):
                             msg = '_!!ERR_out_of_allowed_range!!'
                        elif (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v > 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v > 7):
                            msg = '_!!TODO_BLD_logic!!'
                        if op2_v in op2_value_dict:
                            commands.append(f'{op2_value_dict[op2_v]}{msg}')
                    elif op1_int == 0x30:
                        if op1_int == 1:
                            value = br.read(uint16be)
                            commands.append(f'L {value}')
                        elif op2_int == 2:
                            value = br.read(uint16be)
                            commands.append(f'L 2#{value}')
                        elif op2_int == 3:
                            value = br.read(uint16be)
                            commands.append(f'L {value}')
                        elif op2_int == 5:
                            value = br.read(uint16be)
                            commands.append(f'L {value.decode("utf-16")}')  # decode into unicode
                        elif op2_int == 6:
                            commands.append(f'L B#({br.read(char())},{br.read(char())})')
                        elif op2_int == 7:
                            value = br.read(uint16be)
                            commands.append(f'L W#16#{value}')
                        elif op2_int == 8:
                            value = br.read(uint16be)
                            commands.append(f'L C#{value}')
                        elif op2_int == 9:
                            value = br.read(uint16be)
                            commands.append(f'L D#{value}')  # TODO: convert to date
                        elif op2_int == 0xC:
                            value = br.read(uint16be)
                            commands.append(f'L S5T#{value}MS')  # TODO: convert to Time MS/ H M S
                    elif op1_int == 0x38:
                        if op2_int == 1:
                            value = br.read(uint32be)
                            commands.append(f'L {value}')
                        elif op2_int == 2:
                            value = br.read(uint32be)
                            commands.append(f'L 2#{value}')
                        elif op2_int == 3:
                            value = br.read(uint32be)
                            commands.append(f'L L#{value}')
                        elif op2_int == 4:
                            value = br.read(uint32be)
                            commands.append(f'L P#M{value}')  # decode into unicode
                        elif op2_int == 6:
                            commands.append(
                                f'L B#({br.read(char())},{br.read(char())},{br.read(char())},{br.read(char())})')
                        elif op2_int == 7:
                            value = br.read(uint32be)
                            commands.append(f'L DW#16#{value}')
                        elif op2_int == 9:
                            value = br.read(uint16be)
                            commands.append(f'L T#{value}')  # TODO: convert to date
                        elif op2_int == 0xB:
                            value = br.read(uint16be)
                            commands.append(f'L TOD#{value}MS')  # TODO: convert to Time MS/ H M S
                    elif op1_int == 0x41:
                        value = br.read(uint16be)
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_value_dict = {1: f"= I {value}.{point_v}",
                                          2: f"= Q {value}.{point_v}",
                                          3: f"= M {value}.{point_v}",
                                          4: f"= DBX {value}.{point_v}",
                                          5: f"= DIX {value}.{point_v}",
                                          6: f"= L {value}.{point_v}"
                                          }
                        if (op2_v in [1, 2] and value < 128) or (op2_v in [0x3] and value < 256):
                            msg = '_!!ERR_out_of_allowed_range!!'
                        if op2_v in op2_value_dict:
                            commands.append(f'{op2_value_dict[op2_v]}{msg}')
                    elif op1_int == 0x49:
                        value = br.read(uint16be)
                        point_v = int(op2_str[1],16)
                        op2_v = int(op2_str[0],16)
                        op2_value_dict = {1: f"FP I {value}.{point_v}",
                                          2: f"FP Q {value}.{point_v}",
                                          3: f"FP M {value}.{point_v}",
                                          4: f"FP DBX {value}.{point_v}",
                                          5: f"FP DIX {value}.{point_v}",
                                          6: f"FP L {value}.{point_v}",
                                          9: f"FN I {value}.{point_v}",
                                          0xA: f"FN Q {value}.{point_v}",
                                          0xB: f"FN M {value}.{point_v}",
                                          0xC: f"FN DBX {value}.{point_v}",
                                          0xD: f"FN DI {value}.{point_v}",
                                          0xE: f"FN L {value}.{point_v}",
                                          }
                        if (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v <= 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v <= 7):
                            msg = '_!!ERR_out_of_allowed_range!!'
                        elif (op2_v in [1, 2, 9, 0xA] and value < 128 and point_v > 7) \
                                or (op2_v in [0xB, 0x3] and value < 256 and point_v > 7):
                            msg = '_!!TODO_BLD_logic!!'
                        if op2_v in op2_value_dict:
                            commands.append(f'{op2_value_dict[op2_v]}{msg}')
                    elif op1_int == 0x4A:
                        if op2_int < 0x7F:
                            commands.append(f'L IB {op2_int}')
                        else:
                            commands.append(f'L QB {op2_int & 0x7F}')
                    elif op1_int == 0x4B:
                        if op2_int < 0x7F:
                            commands.append(f'T IB {op2_int}')
                        else:
                            commands.append(f'T QB {op2_int & 0x7F}')
                    elif op1_int == 0x51:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_o = 'A' if point_v <= 6 else 'O'
                        if op2_v > 6:
                            op2_o += 'N'
                        op2_vd = {3: 'MD', 4: 'DBD', 5: 'DID', 6: 'LD', 0xB: 'MD', 0xC: 'DBD', 0xD: 'DID', 0xE: 'LD'}
                        op2_vvd = {1: 'I', 2: 'Q', 3: 'M', 4: 'DBX', 5: 'DIX', 6: 'L',
                                   9: 'I', 0xA: 'Q', 0xB: 'M', 0xC: 'DBX', 0xD: f'DIX', 0xE: f'L'}
                        if op2_v in [5, 0xD]:
                            op2_vvd[0x4] = 'DBD'
                            op2_vvd[0x5] = 'DID'
                            op2_vvd[0xC] = 'DBD'
                            op2_vvd[0xD] = 'DID'
                        elif op2_v in [6, 0xE]:
                            op2_vvd[0x4] = 'DBD'
                            op2_vvd[0x5] = 'DID'
                            op2_vvd[0xC] = 'DBD'
                            op2_vvd[0xD] = 'DID'
                            op2_vvd[0x6] = 'LD'
                            op2_vvd[0xE] = 'LD'
                        commands.append(f'{op2_o} {op2_vvd[point_v]} [{op2_vd[op2_v]} {value}]')
                    elif op1_int == 0x52:
                        if op2_int < 0x7F:
                            commands.append(f'T IW {op2_int}')
                        else:
                            commands.append(f'L Q {op2_int & 0x7F}')
                    elif op1_int == 0x53:
                        if op2_int < 0x7F:
                            commands.append(f'T IW {op2_int}')
                        else:
                            commands.append(f'T Q {op2_int & 0x7F}')
                    elif op1_int == 0x58:
                        value = br.read(uint16be)
                        if op2_int == 0:
                            commands.append(f'+ {twos_complement_hex(value)}')
                        else:
                            op2_str = op2.hex().upper()
                            point_v = int(op2_str[1], 16)
                            op2_v = int(op2_str[0], 16)
                            op2_o = 'X' if point_v <= 6 else 'S'
                            if op2_v > 6:
                                op2_o = 'XN' if point_v <= 6 else 'R'
                            op2_vd = {3: 'MD', 4: 'DBD', 5: 'DID', 6: 'LD', 0xB: 'MD', 0xC: 'DBD', 0xD: 'DID',
                                      0xE: 'LD'}
                            op2_vvd = {1: 'I', 2: 'Q', 3: 'M', 4: 'DBX', 5: 'DIX', 6: 'L',
                                       9: 'I', 0xA: 'Q', 0xB: 'M', 0xC: 'DBX', 0xD: f'DIX', 0xE: f'L'}
                            if op2_v in [5, 0xD]:
                                op2_vvd[0x4] = 'DBD'
                                op2_vvd[0x5] = 'DID'
                                op2_vvd[0xC] = 'DBD'
                                op2_vvd[0xD] = 'DID'
                            elif op2_v in [6, 0xE]:
                                op2_vvd[0x4] = 'DBD'
                                op2_vvd[0x5] = 'DID'
                                op2_vvd[0xC] = 'DBD'
                                op2_vvd[0xD] = 'DID'
                                op2_vvd[0x6] = 'LD'
                                op2_vvd[0xE] = 'LD'
                            commands.append(f'{op2_o} {op2_vvd[point_v]} [{op2_vd[op2_v]} {value}]')
                    elif op1_int == 0x59:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_o = '=' if point_v <= 6 else 'FP'
                        if op2_v > 6:
                            op2_o = 'FN'
                        op2_vd = {3: 'MD', 4: 'DBD', 5: 'DID', 6: 'LD', 0xB: 'MD', 0xC: 'DBD', 0xD: 'DID', 0xE: 'LD'}
                        op2_vvd = {1: 'I', 2: 'Q', 3: 'M', 4: 'DBX', 5: 'DIX', 6: 'L',
                                   9: 'I', 0xA: 'Q', 0xB: 'M', 0xC: 'DBX', 0xD: f'DIX', 0xE: f'L'}
                        if op2_v in [5, 0xD]:
                            op2_vvd[0x4] = 'DBD'
                            op2_vvd[0x5] = 'DID'
                            op2_vvd[0xC] = 'DBD'
                            op2_vvd[0xD] = 'DID'
                        elif op2_v in [6, 0xE]:
                            op2_vvd[0x4] = 'DBD'
                            op2_vvd[0x5] = 'DID'
                            op2_vvd[0xC] = 'DBD'
                            op2_vvd[0xD] = 'DID'
                            op2_vvd[0x6] = 'LD'
                            op2_vvd[0xE] = 'LD'
                        commands.append(f'{op2_o} {op2_vvd[point_v]} [{op2_vd[op2_v]} {value}]')
                    elif op1_int == 0x5A:
                        if op2_int < 0x7F:
                            commands.append(f'L IW {op2_int}')
                        else:
                            commands.append(f'L Q {op2_int & 0x7F}')
                    elif op1_int == 0x5B:
                        if op2_int < 0x7F:
                            commands.append(f'T IW {op2_int}')
                        else:
                            commands.append(f'T Q {op2_int & 0x7F}')
                    elif op1_int == 0x64:
                        commands.append(f'RLD {op2_int}')
                    elif op1_int == 0x60 and op2_int == 0x5:
                        value = br.read(uint32be)
                        commands.append(f'+ {twos_complement_hex(value)}')  # verify
                    elif op1_int == 0x79:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        if op2_v <= 6:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 8: 'A', 9: 'AN', 0xA: 'O',
                                      0xB: 'ON', 0xC: 'X', 0xD: f'XN'}
                        else:
                            op2_vd = {0: 'S', 1: 'R', 2: '=', 4: 'FP', 5: 'FN', 8: 'S', 9: 'R', 0xA: '=',
                                      0xC: 'FP', 0xD: f'FN'}
                        op2_vvd = {0: 'I', 1: 'I', 2: 'Q', 3: 'M', 4: 'DBX', 5: 'DIX', 6: 'L',
                                   9: 'I', 0xA: 'Q', 0xB: 'M', 0xC: 'DBX', 0xD: f'DIX', 0xE: f'L'}
                        arv = 1 if point_v <= 6 else 2
                        commands.append(f'{op2_vd[point_v]} {op2_vvd[op2_v]} [AR{arv},P#{value}]')
                    elif op1_int == 0x7E:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_o = 'L' if point_v < 5 else 'T'
                        op2_vd = {0: 'PI' if point_v <= 3 else 'PQ',
                                  1: 'I',
                                  2: 'Q',
                                  3: 'M',
                                  4: 'DB',
                                  5: 'DI',
                                  6: 'L'}
                        op2_vvd = {1: 'B', 2: 'W', 3: 'D', 5: 'B', 6: 'W', 7: 'D'}
                        commands.append(f'{op2_o} {op2_vd[op2_v]}{op2_vvd[point_v]} {value}')
                    elif op1_int == 0xBA:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_o = 'L' if op2_v <= 6 else 'T'
                        op2_vd = {3: 'MD', 4: 'DBD', 5: 'DID', 6: 'LD', 0xB: 'MD', 0xC: 'DBD', 0xD: 'DID', 0xE: 'LD'}
                        op2_vvd = {0: 'PIB', 1: 'IB', 2: 'QB', 3: 'MB', 4: 'DBB', 5: 'DIB', 6: 'LB'}
                        commands.append(f'{op2_o} {op2_vvd[point_v]} [{op2_vd[op2_v]} {value}]')
                    elif op1_int == 0xBB:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_o = 'L' if op2_v <= 6 else 'T'
                        op2_vd = {3: 'MD', 4: 'DBD', 5: 'DID', 6: 'LD', 0xB: 'MD', 0xC: 'DBD', 0xD: 'DID', 0xE: 'LD'}
                        op2_vvd = {0: 'PIW', 1: 'IW', 2: 'QW', 3: 'MW', 4: 'DBW', 5: 'DIW', 6: 'LW', 8: 'PID',
                                   9: 'ID', 0xA: 'QD', 0xB: 'MD', 0xC: 'DBD', 0xD: f'DID', 0xE: f'LD'}
                        commands.append(f'{op2_o} {op2_vvd[point_v]} [{op2_vd[op2_v]} {value}]')
                    elif op1_int == 0xBE:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        op2_o = {1: 'L', 2: 'L', 3: 'L',
                                 5: 'T', 6: 'T', 7: 'T',
                                 9: 'L', 0xA: 'L', 0xB: 'L',
                                 0xD: 'T', 0xE: 'T', 0xF: 'T'}
                        op2_vd = {1: 'I',
                                  2: 'Q',
                                  3: 'M',
                                  4: 'DB',
                                  5: 'DI',
                                  6: 'L'}
                        op2_vvd = {1: 'B', 2: 'W', 3: 'D',
                                   5: 'B', 6: 'W', 7: 'D',
                                   9: 'B', 0xA: 'W', 0xB: 'D',
                                   0xD: 'B', 0xE: 'W', 0xF: 'D'}
                        arv = 1 if point_v <= 6 else 2
                        commands.append(f'{op2_o[point_v]} {op2_vd[op2_v]}{op2_vvd[point_v]} [AR{arv},P#{value}]')
                    elif op1_int == 0xBF:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        if op2_v <= 6:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 6: 'L', 8: 'FR', 9: 'LC',
                                      0xA: 'SF', 0xB: 'SE', 0xC: 'SD', 0xD: f'SS', 0xE: f'SP', 0xF: f'R'}
                            op2_vdd = 'T'
                        else:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 6: 'L', 8: 'FR', 9: 'LC',
                                      0xA: 'CD', 0xB: f'S', 0xD: f'CU', 0xF: f'R'}
                            op2_vdd = 'C'
                        op2_vvd = {3: 'MW', 4: 'DBW', 5: 'DIW', 6: 'LW',
                                   0xB: 'MW', 0xC: 'DBW', 0xD: f'DIW', 0xE: f'LW'}
                        commands.append(f'{op2_vd[point_v]} {op2_vdd} [{op2_vvd[op2_v]} {value}]')
                    elif op1_int == 0xC0:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.0')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xC1:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.1')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xC2:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.2')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xC3:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.3')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xC4:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.4')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xC5:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.5')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xC6:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.6')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xC7:
                        if op2_int < 0x7F:
                            commands.append(f'A I {op2_int}.7')
                        else:
                            commands.append(f'A Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xC8:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.0')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xC9:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.1')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xCA:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.2')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xCB:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.3')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xCC:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.4')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xCD:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.5')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xCE:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.6')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xCF:
                        if op2_int < 0x7F:
                            commands.append(f'O I {op2_int}.7')
                        else:
                            commands.append(f'O Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xD0:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.0')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xD1:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.1')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xD2:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.2')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xD3:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.3')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xD4:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.4')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xD5:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.5')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xD6:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.6')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xD7:
                        if op2_int < 0x7F:
                            commands.append(f'S I {op2_int}.7')
                        else:
                            commands.append(f'S Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xD8:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.0')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xD9:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.1')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xDA:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.2')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xDB:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.3')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xDC:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.4')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xDD:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.5')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xDE:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.6')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xDF:
                        if op2_int < 0x7F:
                            commands.append(f'= I {op2_int}.7')
                        else:
                            commands.append(f'= Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xE0:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.0')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xE1:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.1')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xE2:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.2')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xE3:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.3')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xE4:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.4')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xE5:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.5')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xE6:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.6')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xE7:
                        if op2_int < 0x7F:
                            commands.append(f'AN I {op2_int}.7')
                        else:
                            commands.append(f'AN Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xE8:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.0')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xE9:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.1')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xEA:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.2')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xEB:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.3')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xEC:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.4')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xED:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.5')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xEE:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.6')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xEF:
                        if op2_int < 0x7F:
                            commands.append(f'ON I {op2_int}.7')
                        else:
                            commands.append(f'ON Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xF0:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.0')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.0')
                    elif op1_int == 0xF1:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.1')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.1')
                    elif op1_int == 0xF2:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.2')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.2')
                    elif op1_int == 0xF3:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.3')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.3')
                    elif op1_int == 0xF4:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.4')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.4')
                    elif op1_int == 0xF5:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.5')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.5')
                    elif op1_int == 0xF6:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.6')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.6')
                    elif op1_int == 0xF7:
                        if op2_int < 0x7F:
                            commands.append(f'R I {op2_int}.7')
                        else:
                            commands.append(f'R Q {op2_int & 0x7f}.7')
                    elif op1_int == 0xFB:
                        value = br.read(uint16be)
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        if op2_v == 0:
                            op2_o = {1: 'L', 2: 'L', 3: 'L',
                                     5: 'T', 6: 'T', 7: 'T',
                                     9: 'L', 0xA: 'L', 0xB: 'L',
                                     0xD: 'T', 0xE: 'T', 0xF: 'T'}
                            op2_vvd = {1: 'B', 2: 'W', 3: 'D',
                                       5: 'B', 6: 'W', 7: 'D',
                                       9: 'B', 0xA: 'W', 0xB: 'D',
                                       0xD: 'B', 0xE: 'W', 0xF: 'D'}
                            arv = 1 if point_v <= 7 else 2
                            commands.append(f'{op2_o[point_v]} {op2_vvd[point_v]} [AR{arv}, P#{value}]')
                        elif op2_v == 1:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 8: 'A', 9: 'AN',
                                      0xA: 'O', 0xB: f'ON', 0xC: f'X', 0xD: f'XN'}
                            commands.append(f'{op2_vd[point_v]} [AR1, P#{value}]')
                        elif op2_v == 2:
                            op2_vd = {0: 'S', 1: 'R', 2: '=', 4: 'FP', 5: 'FN', 8: 'S', 9: 'R',
                                      0xA: '=', 0xC: f'FP', 0xD: f'FN'}
                            commands.append(f'{op2_vd[point_v]} [AR1, P#{value}]')
                        elif op2_v in [3, 4, 5, 6]:
                            op2_vd = {0: 'UC FC', 1: 'CC FC', 2: 'UC FB', 3: 'CC FB', 8: 'OPN DB', 9: 'OPN DI'}
                            op2_vvd = {3: 'MW', 4: 'DBW', 5: 'DIW', 6: 'LW'}
                            commands.append(f'{op2_vd[point_v]} [{op2_vvd[op2_v]} {value}]')
                        elif op2_v == 7:
                            op2_vd = {0: 'UC FC', 1: 'CC FC', 2: 'UC FB', 3: 'CC FB', 4: 'UC SFC', 6: 'UC SFB',
                                      8: 'OPN DB',
                                      9: 'OPN DI'}
                            if point_v not in [4, 6, 9] and int(value, 16) < 256:
                                commands.append('pointer not exist!')
                            else:
                                commands.append(f'{op2_vd[point_v]} {value}')
                        elif op2_v == 8:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN'}
                            commands.append(f'{op2_vd[point_v]} #{value}')
                        elif op2_v == 9:
                            op2_vd = {0: 'S', 1: 'R', 2: '=', 4: 'FP', 5: 'FN'}
                            commands.append(f'{op2_vd[point_v]} #{value}')
                        elif op2_v == 0xA:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 6: 'L', 8: 'FR', 9: 'LC',
                                      0xA: 'SF', 0xB: 'SE', 0xC: 'SD', 0xD: f'SS', 0xE: f'SP', 0xF: f'R'}
                            commands.append(f'{op2_vd[point_v]} #{value}')
                        elif op2_v == 0xB:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 6: 'L', 8: 'FR', 9: 'LC',
                                      0xA: 'CD', 0xB: 'S', 0xD: f'CU', 0xF: f'R'}
                            commands.append(f'{op2_vd[point_v]} C#{value}')
                        elif op2_v == 0xC:
                            op2_vd = {1: 'L B', 2: 'L W', 3: 'L D',
                                      5: 'T B', 6: 'T W', 7: 'T D',
                                      0xA: 'L P##', 0xB: 'L P##'}
                            commands.append(f'{op2_vd[point_v]}{value}')
                        elif op2_v == 0xD:
                            op2_vd = {0: 'UC FC', 2: 'UC FB', 8: 'OPN DB'}
                            commands.append(f'{op2_vd[point_v]}#{value}') #need remove #
                        elif op2_v == 0xE and int(value, 16) >= 256:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 6: 'L', 8: 'FR', 9: 'LC',
                                      0xA: 'SF', 0xB: 'SE', 0xC: 'SD', 0xD: f'SS', 0xE: f'SP', 0xF: f'R'}
                            op2_vdd = 'T'
                            commands.append(f'{op2_vd[point_v]} {op2_vdd}{value}')
                        elif op2_v == 0xF and int(value, 16) >= 256:
                            op2_vd = {0: 'A', 1: 'AN', 2: 'O', 3: 'ON', 4: 'X', 5: 'XN', 6: 'L', 8: 'FR', 9: 'LC',
                                      0xA: 'CD', 0xB: f'S', 0xD: f'CU', 0xF: f'R'}
                            op2_vdd = 'C'
                            if point_v in [0xA, 0xB, 0xD, 0xF]:
                                commands.append(f'{op2_vd[point_v]} {value}')
                            else:
                                commands.append(f'{op2_vd[point_v]} {op2_vdd}{value}')
                    elif op1_int == 0xFE:
                        op2_str = op2.hex().upper()
                        point_v = int(op2_str[1], 16)
                        op2_v = int(op2_str[0], 16)
                        arv = 1 if point_v <= 7 else 2
                        op2_o = {3: 'L', 7: 'T', 0xB: 'L', 0xF: 'T'}
                        if op2_v == 0:
                            if op2_int in [3, 0xB]:
                                value = br.read(uint32be)
                                commands.append(f'LAR{arv} P#{value}')
                            else:
                                value = br.read(uint16be)
                                commands.append(f'+AR{arv} P#{value}')
                        else:
                            value = br.read(uint16be)
                            op2_vvd = {3: 'MD', 4: 'DBD', 5: 'DID', 6: 'LD'}
                            commands.append(f'{op2_o[point_v]}AR{arv} {op2_vvd[op2_v]} {value}')
                    elif op1_int == 0x70:
                        value = br.read(uint16be)
                        op2_o = {8: 'LOOP', 9: 'JL', 0xB: 'JU'}
                        commands.append(f'{op2_o[op2_int]} {value}')
                    elif op1_int == 0xFF:
                        value = br.read(uint16be)
                        op2_o = {0x08: 'JOS', 0x18: 'JO', 0x28: 'JP', 0x48: 'JM', 0x58: 'JUO', 0x68: 'JN', 0x78: 'JNBI',
                                 0x88: 'JZ',
                                 0x98: 'JNB', 0xA8: 'JPZ', 0xB8: 'JCN', 0xC8: 'JMZ', 0xD8: 'JCB', 0xE8: 'JBI',
                                 0xF8: 'JC'}
                        commands.append(f'{op2_o[op2_int]} {value}')
            except (KeyError, StreamNotEnoughData):
                break
        return commands