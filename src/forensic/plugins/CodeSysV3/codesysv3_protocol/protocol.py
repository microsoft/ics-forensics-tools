import netifaces
import struct
from .structures import *
from .constants import *
from .exceptions import CodeSysProtocolV3Exception


class CodeSysV3Protocol:
    PKT_COUNTER = 0
    @staticmethod
    def _build_DatagramLayer(header_size: int, src_address: bytes, dst_address, dg_service: DatagramLayerServices, payload: bytes = b"")  -> bytes:
        dg_layer = bytes(DatagramLayer(dg_service, len(dst_address), len(src_address))) + \
                   dst_address + src_address
        padding_len = (len(dg_layer) + header_size) % 4
        if padding_len != 0:
            dg_layer += b"\x00" * padding_len
        return dg_layer + payload

    @staticmethod
    def build_DatagramLayerRequestOverTCP(src_ip: str, src_port:int, dst_ip: str, dst_port:int,
                                   dg_service: DatagramLayerServices, payload: bytes = b"") -> bytes:
        src_address = bytes(NetworkAddressTCP(src_ip, src_port))
        dst_address = bytes(NetworkAddressTCP(dst_ip, dst_port))
        dg_layer = CodeSysV3Protocol._build_DatagramLayer(ctypes.sizeof(BlockDriverLayerTcp), src_address,
                                                          dst_address,
                                                          dg_service,
                                                          payload)
        return bytes(BlockDriverLayerTcp(len(dg_layer))) + dg_layer

    @staticmethod
    def _get_net_mask(src_ip: str) -> str:
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                for addr in addrs:
                    if addr['addr'] == src_ip:
                        return addr['netmask']
            except:
                pass
        raise Exception(f"Don't find netmask of the src_ip: {src_ip}")


    @staticmethod
    def _get_codesys_address_format(src_ip: str, port: int, netmask: str) -> int:
        netmask_n = int.from_bytes(socket.inet_aton(netmask), "big")
        address = (~netmask_n) & \
                  (int.from_bytes(socket.inet_aton(src_ip), "big"))
        port_index = port - CODESYS_UDP_MIN_PORT

        return address | (port_index << address.bit_length())

    @staticmethod
    def build_NSServerDeviceInfo() -> bytes:
        pkt = bytes(NsHeader(subcmd=NSSubCmd.NameResolve.value, version=0x400, msg_id=CodeSysV3Protocol.PKT_COUNTER))
        CodeSysV3Protocol.PKT_COUNTER += 1
        return pkt

    @staticmethod
    def build_DatagramLayerRequestOverUDP(src_ip: str, src_port: int,
                                   dg_service: DatagramLayerServices, payload: bytes = b"", dst_address: bytes = b"",) -> bytes:
        netmask = CodeSysV3Protocol._get_net_mask(src_ip)
        src_ip_format = CodeSysV3Protocol._get_codesys_address_format(src_ip, src_port, netmask)
        if src_ip_format.bit_length() > 14:
            src_address = src_ip_format.to_bytes(4, "big")
        else:
            src_address = src_ip_format.to_bytes(2, "big")

        return CodeSysV3Protocol._build_DatagramLayer(0, src_address,
                                                          dst_address,
                                                          dg_service,
                                                          payload)

    @staticmethod
    def build_CodeSysChannelLayerOpenRequest() -> bytes:
        pkt = OpenChannelRequest(0x8321d481)
        CodeSysV3Protocol.PKT_COUNTER += 1

        return bytes(pkt)

    @staticmethod
    def build_CodeSysChannelLayerCloseChannel(channel_id: int) -> bytes:
        pkt = CloseChannel(channel_id)

        return bytes(pkt)

    @staticmethod
    def build_CodeSysChannelLayerAck(channel_id, blk_id) -> bytes:
        pkt = ApplicationAck(channel_id=channel_id, blk_id=blk_id)
        return bytes(pkt)

    @staticmethod
    def build_CodeSysChannelLayerAppBlk(channel_id: int, blk_id: int, ack_id: int, payload: bytes, header_size: int = 12)\
            -> typing.List[bytes]:
        first_max_pkt_size = MAX_PDU_SIZE - header_size - ctypes.sizeof(ApplicationBlockFirst)
        second_max_pkt_size = MAX_PDU_SIZE - header_size - ctypes.sizeof(ApplicationBlock)
        first_pkt = bytes(ApplicationBlockFirst(payload, blk_id=blk_id, ack_id=ack_id, channel_id=channel_id)) + \
                    payload[0: first_max_pkt_size]
        pkts = [first_pkt]
        payload_offset = first_max_pkt_size
        while payload_offset < len(payload):
            blk_id += 1
            pkt = bytes(ApplicationBlock(blk_id=blk_id, ack_id=ack_id, channel_id=channel_id)) + \
                    payload[payload_offset: payload_offset + second_max_pkt_size]
            payload_offset += second_max_pkt_size
            pkts.append(pkt)
        return pkts

    @staticmethod
    def build_CodeSysServicesLayer(cmd_group: CmdGroup, subcmd:int, session_id: int,
                                      tags: typing.List[Tag]) -> bytes:
        tags_layer = b""
        for t in tags:
            tags_layer += t.to_stream()
        service_layer = ServiceLayer(cmd_group=cmd_group.value, subcmd=subcmd, session_id=session_id,
                                     content_size=len(tags_layer))
        return bytes(service_layer) + tags_layer

    @staticmethod
    def parse_CodeSysTCPBlockDriverLayer(pkt: bytes) -> list:
        layers = []
        if len(pkt) >= ctypes.sizeof(BlockDriverLayerTcp):
            block_layer = BlockDriverLayerTcp.from_buffer_copy(pkt)
            if block_layer.tcp_magic != TCP_MAGIC:
                raise CodeSysProtocolV3Exception("Not Valid TCP CodeSys magic")
            elif block_layer.tcp_length != len(pkt):
                raise CodeSysProtocolV3Exception(f"Missing pkt bytes, total size:{block_layer.tcp_length}, "
                                                 f"received: {len(pkt)}")
            layers.append(block_layer)
            layers += CodeSysV3Protocol.parse_CodeSysDatagramLayer(pkt, ctypes.sizeof(BlockDriverLayerTcp))
        return layers

    @staticmethod
    def parse_CodeSysDatagramLayer(pkt: bytes, offset: int = 0) -> list:
        layers = []
        if len(pkt) >= ctypes.sizeof(DatagramLayer) + offset:
            dg_layer = DatagramLayer.from_buffer_copy(pkt, offset)
            if dg_layer.dg_magic != DATAGRAM_LAYER_MAGIC:
                raise CodeSysProtocolV3Exception("Not Valid Datagram layer magic")
            total_address_len = 2 * (dg_layer.receiver_len + dg_layer.sender_len)
            padding = (offset + total_address_len + dg_layer.header_length * 2) % 4
            offset += dg_layer.header_length * 2
            dg_layer.receiver_address = pkt[offset: offset + 2 * dg_layer.receiver_len]
            offset += 2 * dg_layer.receiver_len
            dg_layer.sender_address = pkt[offset: offset + 2 * dg_layer.sender_len]
            offset += 2 * dg_layer.sender_len + padding
            layers.append(dg_layer)
            if dg_layer.service_id == DatagramLayerServices.NSClient.value:
                layers += CodeSysV3Protocol.parse_CodeSysNSClient(pkt, offset)
            if dg_layer.service_id == DatagramLayerServices.ChannelManager.value:
                layers += CodeSysV3Protocol.parse_CodeSysChannelLayer(pkt, offset)
        return layers


    @staticmethod
    def parse_CodeSysNSClient(pkt: bytes, offset: int) -> list:
        layers = []
        if len(pkt) >= ctypes.sizeof(NsHeader) + offset:
            nsclient_layer = NsHeader.from_buffer_copy(pkt, offset)
            if nsclient_layer.subcmd == NSSubCmd.DeviceInfo.value and nsclient_layer.version in (0x103, 0x400):
                if len(pkt) >= ctypes.sizeof(NsClientDeviceInfo) + offset:
                    nsclient_device_info_layer = NsClientDeviceInfo.from_buffer_copy(pkt, offset)
                    layers.append(nsclient_device_info_layer)
                    offset += nsclient_device_info_layer.node_name_offset + 48
                    total_strings_name = 2 * (nsclient_device_info_layer.node_name_length +
                                              nsclient_device_info_layer.device_name_length +
                                              nsclient_device_info_layer.vendor_name_length + 3) +\
                                              nsclient_device_info_layer.serial_length
                    if len(pkt) >= offset + total_strings_name:
                        nsclient_device_info_layer.node_name = pkt[offset:offset + 2*(nsclient_device_info_layer.node_name_length)].decode('UTF-16-LE')
                        offset += 2*(nsclient_device_info_layer.node_name_length + 1)
                        nsclient_device_info_layer.device_name = pkt[offset:offset + 2 * (nsclient_device_info_layer.device_name_length)].decode('UTF-16-LE')
                        offset += 2 * (nsclient_device_info_layer.device_name_length + 1)
                        nsclient_device_info_layer.vendor_name = pkt[offset:offset + 2 * (nsclient_device_info_layer.vendor_name_length)].decode('UTF-16-LE')
                        offset += 2 * (nsclient_device_info_layer.vendor_name_length + 1)
                        nsclient_device_info_layer.serial = pkt[offset:offset + nsclient_device_info_layer.serial_length].decode('ascii')
                        nsclient_device_info_layer.firmware_str = f"{nsclient_device_info_layer.firmware[3]}.{nsclient_device_info_layer.firmware[2]}.{nsclient_device_info_layer.firmware[1]}.{nsclient_device_info_layer.firmware[0]}"

        return layers

    @staticmethod
    def parse_CodeSysChannelLayer(pkt: bytes, offset: int) -> list:
        if len(pkt) >= offset + 1:
            type = pkt[offset]
            if type == ChannelLayerType.ApplicationBlock.value:
                return CodeSysV3Protocol.parse_CodeSysChannelLayerAppBlk(pkt, offset)
            if type == ChannelLayerType.OpenChannelResponse.value:
                return CodeSysV3Protocol.parse_OpenChannelResponse(pkt, offset)
            elif type == ChannelLayerType.ApplicationAck.value:
                return CodeSysV3Protocol.parse_CodeSysChannelLayerAppAck(pkt, offset)
            elif type == ChannelLayerType.CloseChannel.value:
                return CodeSysV3Protocol.parse_CodeSysChannelLayerOpenChannelRes(pkt, offset)
            elif type == ChannelLayerType.KeepAlive.value:
                return CodeSysV3Protocol.parse_CodeSysChannelLayerKeepAlive(pkt, offset)
        return []

    @staticmethod
    def parse_CodeSysChannelLayerKeepAlive(pkt: bytes, offset: int) -> list:
        if len(pkt) >= offset + ctypes.sizeof(KeepLive):
            return [KeepLive.from_buffer_copy(pkt, offset)]
        return []

    @staticmethod
    def parse_CodeSysChannelLayerAppBlk(pkt: bytes, offset: int) -> list:
        if len(pkt) >= offset + 2:
            flags = pkt[offset + 1]
            if flags & 0x01 and len(pkt) >= offset + ctypes.sizeof(ApplicationBlockFirst):
                return [ApplicationBlockFirst.from_buffer_copy(pkt, offset),
                        pkt[offset + ctypes.sizeof(ApplicationBlockFirst):]]
            elif len(pkt) >= offset + ctypes.sizeof(ApplicationBlock):
                return [ApplicationBlock.from_buffer_copy(pkt, offset),
                        pkt[offset + ctypes.sizeof(ApplicationBlock):]]
        return []

    @staticmethod
    def parse_CodeSysChannelLayerAppAck(pkt: bytes, offset: int) -> list:
        if len(pkt) >= offset + ctypes.sizeof(ApplicationAck):
            return [ApplicationAck.from_buffer_copy(pkt, offset)]
        return []

    @staticmethod
    def parse_OpenChannelResponse(pkt: bytes, offset: int) -> list:
        if len(pkt) >= offset + ctypes.sizeof(OpenChannelResponse):
            return [OpenChannelResponse.from_buffer_copy(pkt, offset)]
        return []

    @staticmethod
    def parse_CodeSysChannelLayerOpenChannelRes(pkt: bytes, offset: int) -> list:
        if len(pkt) >= offset + ctypes.sizeof(OpenChannelResponse):
            return [OpenChannelResponse.from_buffer_copy(pkt, offset)]
        return []

    @staticmethod
    def parse_CodeSysServiceLayer(pkt: bytes) -> typing.Tuple[ServiceLayer, typing.Dict[int, Tag]]:
        if len(pkt) >= ctypes.sizeof(ServiceLayer):
            service_layer = ServiceLayer.from_buffer_copy(pkt)
            if service_layer.protocol_id == ProtocolID.Normal.value:
                offset = service_layer.header_size + 4
                tags = CodeSysV3Protocol.parse_TagsLayer(pkt, offset)
                return [service_layer, tags]
            return [service_layer, None]
        return [None, None]

    @staticmethod
    def parse_TagsLayer(pkt: bytes, offset: int) -> typing.Dict[int, Tag]:
        tags = {}
        while offset < len(pkt):
            tag, offset = Tag.from_stream(pkt, offset)
            if tag.id in tags and isinstance(tags[tag.id], Tag):
                tags[tag.id] = []
            if tag.id in tags:
                tags[tag.id].append(tag)
            else:
                tags[tag.id] = tag
        return tags