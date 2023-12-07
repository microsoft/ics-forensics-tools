import base64
import binascii
import struct
import io
from enum import Enum
from typing import Any, Type, List, Tuple
import sys
import hexdump
import string

PRINTABLE_CHARS = set(bytes(string.printable, 'ascii'))
DEBUG_PRINT = False


def decode_ascii(data):
    return ''.join([chr(char) if char in PRINTABLE_CHARS else '?' for char in data])


class Endianness(Enum):
    DEFAULT = 0
    LITTLE = 1
    BIG = 2


class Sign(Enum):
    NONE = 0
    SIGNED = 1
    UNSIGNED = 2


class DataType(Enum):
    INTEGER = 1
    FLOAT = 2
    BYTES = 3
    ASCII_STRING = 4
    NULL_TERMNINATED_ASCII_STRING = 5
    DYNAMIC = 6


BITS_8 = 1
BITS_16 = 2
BITS_32 = 4
BITS_64 = 8


class BasicType:
    def __init__(self, data_type: DataType, size: int, sign: Sign, endianness: Endianness):
        self.data_type = data_type
        self.size = size
        self.sign = sign
        self.endianness = endianness


byte = BasicType(DataType.INTEGER, BITS_8, Sign.SIGNED, Endianness.DEFAULT)
ubyte = BasicType(DataType.INTEGER, BITS_8, Sign.UNSIGNED, Endianness.DEFAULT)

char = BasicType(DataType.BYTES, BITS_8, Sign.SIGNED, Endianness.DEFAULT)

int16 = BasicType(DataType.INTEGER, BITS_16, Sign.SIGNED, Endianness.DEFAULT)
uint16 = BasicType(DataType.INTEGER, BITS_16, Sign.UNSIGNED, Endianness.DEFAULT)
int16be = BasicType(DataType.INTEGER, BITS_16, Sign.SIGNED, Endianness.BIG)
int16le = BasicType(DataType.INTEGER, BITS_16, Sign.SIGNED, Endianness.LITTLE)
uint16be = BasicType(DataType.INTEGER, BITS_16, Sign.UNSIGNED, Endianness.BIG)
uint16le = BasicType(DataType.INTEGER, BITS_16, Sign.UNSIGNED, Endianness.LITTLE)

int32 = BasicType(DataType.INTEGER, BITS_32, Sign.SIGNED, Endianness.DEFAULT)
uint32 = BasicType(DataType.INTEGER, BITS_32, Sign.UNSIGNED, Endianness.DEFAULT)
int32be = BasicType(DataType.INTEGER, BITS_32, Sign.SIGNED, Endianness.BIG)
int32le = BasicType(DataType.INTEGER, BITS_32, Sign.SIGNED, Endianness.LITTLE)
uint32be = BasicType(DataType.INTEGER, BITS_32, Sign.UNSIGNED, Endianness.BIG)
uint32le = BasicType(DataType.INTEGER, BITS_32, Sign.UNSIGNED, Endianness.LITTLE)

int64 = BasicType(DataType.INTEGER, BITS_64, Sign.SIGNED, Endianness.DEFAULT)
uint64 = BasicType(DataType.INTEGER, BITS_64, Sign.UNSIGNED, Endianness.DEFAULT)
int64be = BasicType(DataType.INTEGER, BITS_64, Sign.SIGNED, Endianness.BIG)
int64le = BasicType(DataType.INTEGER, BITS_64, Sign.SIGNED, Endianness.LITTLE)
uint64be = BasicType(DataType.INTEGER, BITS_64, Sign.UNSIGNED, Endianness.BIG)
uint64le = BasicType(DataType.INTEGER, BITS_64, Sign.UNSIGNED, Endianness.LITTLE)

floatne = BasicType(DataType.FLOAT, BITS_32, Sign.SIGNED, Endianness.DEFAULT)
floatbe = BasicType(DataType.FLOAT, BITS_32, Sign.SIGNED, Endianness.BIG)
floatle = BasicType(DataType.FLOAT, BITS_32, Sign.SIGNED, Endianness.LITTLE)

double = BasicType(DataType.FLOAT, BITS_64, Sign.SIGNED, Endianness.DEFAULT)
doublebe = BasicType(DataType.FLOAT, BITS_64, Sign.SIGNED, Endianness.BIG)
doublele = BasicType(DataType.FLOAT, BITS_64, Sign.SIGNED, Endianness.LITTLE)
dynamic = BasicType(DataType.DYNAMIC, 0, Sign.NONE, Endianness.DEFAULT)


def bytesne(x): return BasicType(DataType.BYTES, x, Sign.NONE, Endianness.DEFAULT)


def bytesle(x): return BasicType(DataType.BYTES, x, Sign.NONE, Endianness.LITTLE)


def bytesbe(x): return BasicType(DataType.BYTES, x, Sign.NONE, Endianness.BIG)


def ascii_string(x): return BasicType(DataType.ASCII_STRING, x, Sign.NONE, Endianness.DEFAULT)


def nt_ascii_string(x): return BasicType(DataType.NULL_TERMNINATED_ASCII_STRING, x, Sign.NONE, Endianness.DEFAULT)


class DataStruct:
    def __init__(self, br=None) -> None:
        if br:
            for key, val in br.read_struct(self.__class__).items():
                self.__setattr__(key, val)

    @classmethod
    def get_members(cls: object) -> List[Tuple[str, BasicType]]:
        return list(filter(lambda x: not x[0].startswith('__') and not x[0].startswith('__'),
                           cls.__dict__.items()))

    @classmethod
    def get_size(cls: object):
        size = 0

        for field, dt in cls.get_members():
            size += dt.size

        return size


def data_struct_serializer(obj):
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('ascii')
    else:
        raise TypeError(f'Object of type {type(obj)} is not JSON serializable')


class StreamNotEnoughData(Exception):
    pass


class BinaryStream(object):
    DEBUG_DATA = {}

    def __init__(self, base_stream: bytes = b'', endianness: Endianness = Endianness.LITTLE) -> None:
        if self not in BinaryStream.DEBUG_DATA:
            BinaryStream.DEBUG_DATA[self] = []

        self._int_size_map = {BITS_8: 'b',
                              BITS_16: 'h',
                              BITS_32: 'i',
                              BITS_64: 'q'}

        self._float_size_map = {BITS_32: 'f',
                                BITS_64: 'd'}

        self._endianness = endianness
        self._base_stream = io.BytesIO(base_stream)

    def _is_le(self, endianness: Endianness) -> bool:
        true_endianness = self._endianness if endianness == Endianness.DEFAULT else endianness

        return true_endianness == Endianness.LITTLE

    def _get_le_sign(self, endianness: Endianness) -> str:
        return '<' if self._is_le(endianness) else '>'

    def _build_struct_format(self, dt: DataType, size: int, sign: Sign, endianness: Endianness) -> str:
        code = None

        if dt == DataType.INTEGER:
            code = self._int_size_map[size]

            if sign == Sign.UNSIGNED:
                code = code.upper()

            code = self._get_le_sign(endianness) + code
        elif dt == DataType.FLOAT:
            code = self._get_le_sign(endianness) + self._float_size_map[size]
        elif dt in [DataType.BYTES, DataType.ASCII_STRING, DataType.NULL_TERMNINATED_ASCII_STRING]:
            code = f'{size}s'

        return code

    def _seek(self, pos: int, whence: int = 0) -> None:
        self._base_stream.seek(pos, whence)

    def _tell(self) -> int:
        return self._base_stream.tell()

    def dump(self) -> bytes:
        pos = self._tell()
        self._seek(0)
        data = self._base_stream.read()
        self._seek(pos)

        return data

    def __bytes__(self) -> bytes:
        return self.dump()

    def __len__(self) -> int:
        pos = self._tell()
        self._seek(0, 2)
        size = self._tell()
        self._seek(pos)
        return size

    def _debug_print(self, basic_type: BasicType, obj, dt_name):
        if dt_name is None:
            if basic_type.data_type == DataType.BYTES:
                dt_name = 'bytes'
            elif basic_type.data_type == DataType.ASCII_STRING:
                dt_name = 'ascii'
            elif basic_type.data_type == DataType.NULL_TERMNINATED_ASCII_STRING:
                dt_name = 'null terminated ascii'
            else:
                dt_name = list(filter(lambda x: x[1] == basic_type, sys.modules[__name__].__dict__.items()))[0][0]

        obj_repr = None

        if basic_type.data_type == DataType.INTEGER:
            obj_repr = ('0x%0' + str(basic_type.size) + 'X') % obj
        elif basic_type.data_type == DataType.FLOAT:
            obj_repr = '%.3f' % obj
        elif basic_type.data_type == DataType.BYTES:
            obj_repr = binascii.hexlify(obj)
        elif basic_type.data_type == DataType.ASCII_STRING:
            obj_repr = obj
        elif basic_type.data_type == DataType.NULL_TERMNINATED_ASCII_STRING:
            obj_repr = obj

        pos = self._tell()
        self._seek(pos - basic_type.size)
        raw = self._base_stream.read(basic_type.size)

        BinaryStream.DEBUG_DATA[self].append((dt_name, obj_repr, raw, basic_type.size))


class BinaryReader(BinaryStream):
    def _unpack(self, fmt: str, length: int) -> Any:
        return struct.unpack(fmt, self._base_stream.read(length))[0]

    def _unpack_tp(self, fmt: str, length: int):
        return struct.unpack(fmt, self._base_stream.read(length))

    def peek_bytes(self, length: int) -> bytes:
        pos = self._tell()
        res = self.read(bytesbe(length))
        self._seek(pos)

        return res

    def peek(self, basic_type: BasicType) -> Any:
        return struct.unpack(self._build_struct_format(basic_type.data_type, basic_type.size,
                                                       basic_type.sign, basic_type.endianness),
                             self.peek_bytes(basic_type.size))[0]

    def read(self, basic_type: BasicType, dt_name=None, enable_check=True) -> Any:
        if enable_check and basic_type.size > self.remaining_data():
            raise StreamNotEnoughData()

        obj = self._unpack(self._build_struct_format(basic_type.data_type, basic_type.size,
                                                     basic_type.sign, basic_type.endianness), basic_type.size)

        # Post-processing
        if basic_type.data_type == DataType.ASCII_STRING:
            obj = obj.decode('ascii', 'replace')
        elif basic_type.data_type == DataType.NULL_TERMNINATED_ASCII_STRING:
            obj = obj.decode('ascii', 'replace')
            obj = obj[:obj.find('\x00')]
        elif basic_type.data_type == DataType.BYTES:
            if self._is_le(basic_type.endianness) and basic_type.size > 1:
                obj = obj[::-1]

        if DEBUG_PRINT:
            self._debug_print(basic_type, obj, dt_name)

        return obj

    def read_struct(self, struct_class: Type[DataStruct]) -> dict:
        res = {}

        for field, dt in struct_class.get_members():
            if dt != dynamic:
                res[field] = self.read(dt, f'{struct_class.__name__}.{field}')

        return res

    def remaining_data(self) -> int:
        return len(self) - self._tell()

    def seek(self, pos: int, whence: int = 0) -> None:
        self._seek(pos, whence)

    def tell(self):
        return self._tell()


class BinaryWriter(BinaryStream):
    def __init__(self, endianness: Endianness = Endianness.LITTLE) -> None:
        super().__init__(b'', endianness)

    def _pack(self, fmt: str, data: Any) -> None:
        self._base_stream.write(struct.pack(fmt, data))

    def write(self, basic_type: BasicType, value, dt_name=None) -> None:
        # Pre-processing
        if basic_type.data_type == DataType.ASCII_STRING:
            value = value.encode('ascii')
        elif basic_type.data_type == DataType.NULL_TERMNINATED_ASCII_STRING:
            value = value[:value.find('\x00')]
            value = value.decode('ascii', 'replace')
        elif basic_type.data_type == DataType.BYTES:
            if self._is_le(basic_type.endianness):
                value = value[::-1]

        self._pack(self._build_struct_format(basic_type.data_type, basic_type.size,
                                             basic_type.sign, basic_type.endianness), value)

        if DEBUG_PRINT:
            self._debug_print(basic_type, value, dt_name)

    def write_struct(self, struct_class: Type[DataStruct], struct_data: dict) -> None:
        for field, dt in struct_class.get_members():
            if field in struct_data and dt != dynamic:
                self.write(dt, struct_data[field], f'{struct_class.__name__}.{field}')

    def __add__(self, other):
        bw = BinaryWriter()
        bw.write(bytesbe(len(self)), self.dump())
        bw.write(bytesbe(len(other)), other.dump())

        if DEBUG_PRINT:
            if other not in BinaryStream.DEBUG_DATA:
                BinaryStream.DEBUG_DATA[other] = []

            BinaryStream.DEBUG_DATA[bw] = BinaryStream.DEBUG_DATA[self] + BinaryStream.DEBUG_DATA[other]
            del BinaryStream.DEBUG_DATA[self]
            del BinaryStream.DEBUG_DATA[other]

        return bw

    def __iadd__(self, other):
        self.write(bytesbe(len(other)), other.dump())

        if DEBUG_PRINT:
            BinaryStream.DEBUG_DATA[self] += BinaryStream.DEBUG_DATA[other]
            del BinaryStream.DEBUG_DATA[other]

        return self


def debug_print():
    print_res = ''

    for key, val in BinaryStream.DEBUG_DATA.items():
        all_data = b''
        if len(val) == 0:
            continue

        if isinstance(key, BinaryReader):
            spaces = 10
            print_res += 'BinaryReader\n'
        else:
            spaces = 0
            print_res += 'BinaryWriter\n'

        for item in val:
            dt_name, obj_repr, raw, size = item
            all_data += raw
            print_res += (' ' * spaces + f'{dt_name} = {obj_repr} -> {hexdump.dump(raw)}\n')
            # + str(size) + ': ' + hexdump.dump(raw)+'\n'
        print_res += hexdump.hexdump(all_data, result='return') + '\n'
        print_res += ('-' * 80) + '\n'

    return print_res
