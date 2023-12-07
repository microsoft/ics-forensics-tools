import ctypes
import enum
import socket,struct
import zlib, typing
from .exceptions import CodeSysProtocolV3Exception
from .constants import *

class BaseLittleEndianStructure(ctypes.LittleEndianStructure):
    _defaults_ = {}
    _pack_ = 1
    def __init__(self, **kwargs):
        values = type(self)._defaults_.copy()
        values.update(kwargs)
        super().__init__(**values)


class BlockDriverLayerTcp(BaseLittleEndianStructure):
    _fields_ = [
        ("tcp_magic", ctypes.c_uint32),
        ("tcp_length", ctypes.c_uint32)
    ]
    _defaults_ = {
        "tcp_magic": TCP_MAGIC
    }

    def __init__(self, payload_len: int):
        super(BlockDriverLayerTcp, self).__init__(
            tcp_length=ctypes.sizeof(BlockDriverLayerTcp) + payload_len
        )


class DatagramLayerServices(enum.Enum):
    AddressNotificationRequest = 1
    AddressNotificationResponse = 2
    NSServer = 3
    NSClient = 4
    ChannelManager = 64


class ChannelLayerType(enum.Enum):
    ApplicationBlock = 0x01
    ApplicationAck = 0x02
    KeepAlive = 0x03
    GetInfo = 0xc2
    OpenChannelRequest = 0xc3
    CloseChannel = 0xc4
    OpenChannelResponse = 0x83

class Priority(enum.Enum):
    Low = 0
    Normal = 1
    High = 2
    Emergency = 3


class AddressType(enum.Enum):
    Full = 0
    Relative = 1


class Boolean(enum.Enum):
    TRUE = 1
    FALSE = 0


class NSSubCmd(enum.Enum):
    DeviceInfo = 0xc280
    NameResolve = 0xc202
    AddressResolve = 0xc201


class ProtocolID(enum.Enum):
    Normal = 0xcd55
    Secure = 0x7557


class CmdGroup(enum.Enum):
    CmpAlarmManager = 0x18
    CmpApp = 0x02
    CmpAppBP = 0x12
    CmpAppForce = 0x13
    CmpCodeMeter = 0x1d
    CmpCoreDump = 0x1f
    CmpDevice = 0x01
    CmpFileTransfer = 0x08
    CmpIecVarAccess = 0x09
    CmpIoMgr = 0x0b
    CmpLog = 0x05
    CmpMonitor = 0x1b
    CmpOpenSSL = 0x22
    CmpSettings = 0x06
    CmpTraceMgr = 0x0f
    CmpUserMgr = 0x0c
    CmpVisuServer = 0x04
    PlcShell = 0x11
    SysEthernet = 0x07



class DatagramLayer(BaseLittleEndianStructure):
    _fields_ = [
        ("dg_magic", ctypes.c_uint8),

        ("header_length", ctypes.c_uint8, 3),
        ("hop_count", ctypes.c_uint8, 5),

        ("length_data_block", ctypes.c_uint8, 4),
        ("signal", ctypes.c_uint8, 1),
        ("type_address", ctypes.c_uint8, 1),
        ("priority", ctypes.c_uint8, 2),

        ("service_id", ctypes.c_uint8),
        ("message_id", ctypes.c_uint8),

        ("receiver_len", ctypes.c_uint8, 4),
        ("sender_len", ctypes.c_uint8, 4),
    ]

    _defaults_ = {
        "dg_magic": DATAGRAM_LAYER_MAGIC,
        "hop_count": 13,
        "header_length": 3,
        "priority": Priority.Normal.value,
        "signal": Boolean.FALSE.value,
        "type_address": AddressType.Full.value,
        "length_data_block": 0
    }
    
    def __init__(self, service: DatagramLayerServices, receiver_len: int, sender_len: int, message_id: int=0):
        super(DatagramLayer, self).__init__(
            service_id=service.value,
            message_id=message_id,
            receiver_len=int(receiver_len / 2),
            sender_len=int(sender_len / 2),
        )

class NetworkAddressTCP(ctypes.BigEndianStructure):
    _fields_ = [
        ("port", ctypes.c_uint16),
        ("address", ctypes.c_ubyte * 4),
    ]

    def __init__(self, ip: str, port: int):
        super(NetworkAddressTCP, self).__init__()
        ip_bytes = (ctypes.c_ubyte * 4)()
        ip_bytes[:] = socket.inet_aton(ip)
        self.port = port
        self.address = ip_bytes

class NsHeader(BaseLittleEndianStructure):
    _fields_ = [
        ("subcmd", ctypes.c_uint16),
        ("version", ctypes.c_uint16),
        ("msg_id", ctypes.c_uint32),
    ]


class NsClientDeviceInfo(BaseLittleEndianStructure):
    _fields_ = [
        ("subcmd", ctypes.c_uint16),
        ("version", ctypes.c_uint16),
        ("msg_id", ctypes.c_uint32),
        ("max_channels", ctypes.c_uint16),
        ("byte_order", ctypes.c_ubyte),
        ("unk1", ctypes.c_ubyte),
        ("node_name_offset", ctypes.c_uint16),
        ("node_name_length", ctypes.c_uint16),
        ("device_name_length", ctypes.c_uint16),
        ("vendor_name_length", ctypes.c_uint16),
        ("target_type", ctypes.c_uint16),
        ("target_id", ctypes.c_uint16),
        ("unk2", ctypes.c_uint32),
        ("firmware", 4*ctypes.c_ubyte),
        ("unk3", ctypes.c_uint32),
        ("serial_length", ctypes.c_uint8),
    ]


class OpenChannelRequest(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("version", ctypes.c_uint16),
        ("checksum", ctypes.c_uint32),
        ("msg_id", ctypes.c_uint32),
        ("receiver_buffer_size", ctypes.c_uint32),
        ("unk1", ctypes.c_uint32)
    ]

    _defaults_ = {
        "type": ChannelLayerType.OpenChannelRequest.value,
        "flags": 0x00,
        "version": 0x0101,
        "checksum": 0,
        "receiver_buffer_size": 0x001f4000,
        "unk1": 0x05
    }

    def __init__(self, msg_id: int):
        super(OpenChannelRequest, self).__init__()
        self.msg_id = msg_id
        self.update_checksum()

    def update_checksum(self):
        self.checksum = zlib.crc32(bytes(self))


class CloseChannel(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("version", ctypes.c_uint16),
        ("checksum", ctypes.c_uint32),
        ("channel_id", ctypes.c_uint16),
        ("reason", ctypes.c_uint16),
    ]

    _defaults_ = {
        "type": ChannelLayerType.CloseChannel.value,
        "flags": 0x00,
        "version": 0x0101,
        "checksum": 0,
        "reason": 0
    }

    def __init__(self, channel_id: int):
        super(CloseChannel, self).__init__()
        self.channel_id = channel_id
        self.update_checksum()

    def update_checksum(self):
        self.checksum = zlib.crc32(bytes(self))


class OpenChannelResponse(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("version", ctypes.c_uint16),
        ("checksum", ctypes.c_uint32),
        ("msg_id", ctypes.c_uint32),
        ("reason", ctypes.c_uint16),
        ("channel_id", ctypes.c_uint16),
        ("receiver_buffer_size", ctypes.c_uint32),
        ("unk1", ctypes.c_uint32)
    ]

    _defaults_ = {
        "type": ChannelLayerType.OpenChannelResponse.value,
        "flags": 0x00,
        "version": 0x0101,
        "checksum": 0,
        "reason": 0,
        "receiver_buffer_size": 0x001f4000,
        "unk1": 0x04,

    }

    def __init__(self, msg_id: int, channel_id: int):
        super(OpenChannelResponse, self).__init__()
        self.msg_id = msg_id
        self.channel_id = channel_id
        self.update_checksum()

    def update_checksum(self):
        self.checksum = zlib.crc32(bytes(self))


class ApplicationAck(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("channel_id", ctypes.c_uint16),
        ("blk_id", ctypes.c_uint32)
    ]

    _defaults_ = {
        "flags": 0x80,
        "type": ChannelLayerType.ApplicationAck.value
    }


class KeepLive(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("channel_id", ctypes.c_uint16),
    ]

    _defaults_ = {
        "flags": 0x00,
        "type": ChannelLayerType.KeepAlive.value
    }


class ApplicationBlockFirst(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("is_first_payload", ctypes.c_ubyte, 7),
        ("is_request", ctypes.c_ubyte, 1),
        ("channel_id", ctypes.c_uint16),
        ("blk_id", ctypes.c_uint32),
        ("ack_id", ctypes.c_uint32),
        ("remaining_data_size", ctypes.c_uint32),
        ("checksum", ctypes.c_uint32),
    ]

    _defaults_ = {
        "is_first_payload": 1,
        "is_request": 1,
        "checksum": 0,
        "type": ChannelLayerType.ApplicationBlock.value
    }

    def __init__(self, payload, *args, **kwargs):
        super(ApplicationBlockFirst, self).__init__(*args, **kwargs)
        self.remaining_data_size = len(payload)
        self.checksum = zlib.crc32(bytes(payload))


class ApplicationBlock(BaseLittleEndianStructure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("is_first_payload", ctypes.c_ubyte, 7),
        ("is_request", ctypes.c_ubyte, 1),
        ("channel_id", ctypes.c_uint16),
        ("blk_id", ctypes.c_uint32),
        ("ack_id", ctypes.c_uint32),
    ]

    _defaults_ = {
        "is_first_payload": 0,
        "is_request": 1,
        "type": ChannelLayerType.ApplicationBlock.value
    }


class ServiceLayer(BaseLittleEndianStructure):
    _fields_ = [
        ("protocol_id", ctypes.c_uint16),
        ("header_size", ctypes.c_uint16),
        ("cmd_group", ctypes.c_uint16, 7),
        ("is_response", ctypes.c_uint16, 1),
        ("subcmd", ctypes.c_uint16),
        ("session_id", ctypes.c_uint32),
        ("content_size", ctypes.c_uint32)
    ]

    _defaults_ = {
        "protocol_id": ProtocolID.Normal.value,
        "header_size": 12,
        "is_response": 0,
        "additional_data": 0
    }


class Tag:

    DATA_FORMAT = {
        "dword": ">I",
        "word": ">H",
        "byte": ">B",
        "char": ">c",
        "long": ">Q",
        "dword_le": "<I",

    }

    def __init__(self, id:int, data:bytes = b"", align: int = 0x40):
        self.id = id
        self._sub_tags = {}
        self.data = data
        self._align = align

    @property
    def is_parent(self):
        return self.id >= 0x80

    def __getitem__(self, tag_id):
        return self._sub_tags.get(tag_id)

    @staticmethod
    def _read_tag_number(stream: bytes, offset: int) -> typing.Tuple[int, int]:
        if len(stream) <= offset:
            raise CodeSysProtocolV3Exception("Not enough data for tag")
        t = stream[offset]
        n = t & 0x7f
        shift = 7
        while (t & 0x80) != 0:
            offset += 1
            if len(stream) <= offset:
                raise CodeSysProtocolV3Exception("Not enough data for tag")
            t = stream[offset]
            n |= ((t & 0x7f) << shift)
            shift += 7

        return n, offset + 1

    @staticmethod
    def _write_tag_number(v: int) -> bytes:
        b = b""
        while v > 0:
            t = v & 0x7f
            v >>= 7
            if v > 0:
                t |= 0x80
            b += bytes([t])

        return b

    def add_tag(self, subtag):
        if subtag.id in self._sub_tags and isinstance(self._sub_tags[subtag.id], Tag):
            self._sub_tags[subtag.id] = []
        if subtag.id in self._sub_tags:
            self._sub_tags[subtag.id].append(subtag)
        else:
            self._sub_tags[subtag.id] = subtag

    def get_tag(self, id:int):
        return self._sub_tags.get(id)

    @staticmethod
    def from_stream(stream: bytes, offset: int = 0):
        tag_id, offset = Tag._read_tag_number(stream, offset)
        tag_size, offset = Tag._read_tag_number(stream, offset)
        if len(stream) < offset + tag_size:
            raise CodeSysProtocolV3Exception("Not enough data for tag")
        data = stream[offset: offset + tag_size]
        tag = Tag(tag_id, data)
        if tag.is_parent:
            toffset = 0
            while tag_size > toffset:
                sub_tag, toffset = Tag.from_stream(data, toffset)
                tag.add_tag(sub_tag)
        return tag, offset + tag_size

    def _add_align_to_size(self, tag_id_size: int, tag_size_length: int):
        align_modulus = (self._align & 0xF0) >> 4
        align_remainder = (self._align & 0x0F)

        total_header_size = tag_id_size + tag_size_length
        total_header_size_mod = total_header_size % align_modulus

        if total_header_size_mod < align_remainder:
            total_header_size += align_remainder - total_header_size_mod
        elif total_header_size_mod > align_remainder:
            total_header_size += align_modulus - (total_header_size_mod - align_remainder)

        return total_header_size

    def to_stream(self) -> bytes:
        tag_id = Tag._write_tag_number(self.id)
        data = self.data
        if self.is_parent:
            sub_tags_data = b""
            for t in self._sub_tags.values():
                sub_tags_data += t.to_stream()
            data = sub_tags_data
        tag_size = Tag._write_tag_number(len(data))
        header = bytearray(tag_id + tag_size)
        total_size = self._add_align_to_size(len(tag_id), len(tag_size))
        for i in range(total_size - len(header)):
            header[len(header) - 1] |= 0x80
            header.append(0)
        return header + data

    def __getattr__(self, item):
        if item in Tag.DATA_FORMAT:
            return struct.unpack(Tag.DATA_FORMAT[item], self.data)[0]

