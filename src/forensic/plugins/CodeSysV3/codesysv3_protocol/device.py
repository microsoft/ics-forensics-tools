import enum
import socket
import logging
from .constants import *
from .exceptions import *
from .structures import *
from .protocol import *
from .channel import CodeSysV3Channel

class DatagramLayerType(enum.Enum):
    TCP = 1
    UDP = 2


class CodeSysV3Device:
    TCP_PORT = 11740
    UDP_PORT = 1740

    def __init__(self, dst_device_ip, interface_ip):
        self._src_ip = interface_ip
        self._dst_ip = dst_device_ip
        self.logger = logging.getLogger(self.__class__.__name__)
        self._datagram_type = None
        self._dst_address = b""

    def _prepared_socket(self):
        if self._datagram_type == DatagramLayerType.TCP:
            self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            self._socket.bind(('', 0))
            self._socket.settimeout(5)
            self._src_port = self._socket.getsockname()[1]
            self._dst_port = CodeSysV3Device.TCP_PORT
        else:
            self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
            self._socket.bind(('', CodeSysV3Device.UDP_PORT))
            self._socket.settimeout(5)
            self._src_port = CodeSysV3Device.UDP_PORT
            self._dst_port = CodeSysV3Device.UDP_PORT

    def connect(self):
        self.logger.info(f"Starting to connect to the device {self._dst_ip}")
        if self._datagram_type is None:
            self._datagram_type = self._determine_datagram_layer_type()
            self._prepared_socket()

        if self._datagram_type == DatagramLayerType.TCP:
            self._socket.connect((self._dst_ip, self._dst_port))
        self.logger.info("Connected to the device")

    def is_connected(self):
        return self._datagram_type is not None

    def close(self):
        if self.is_connected():
            self.logger.info("Closing the connection")
            self._socket.close()
            self._datagram_type = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def send_pdu(self, service: DatagramLayerServices, pkt: bytes):
        pkt = self._prepared_datagram_layer(service, pkt)
        if self._datagram_type == DatagramLayerType.TCP:
            self._socket.sendall(pkt)
        else:
            self._socket.sendto(pkt, (self._dst_ip, self._dst_port))

    def recv_pdu(self) -> list:
        if self._datagram_type == DatagramLayerType.TCP:
            pdu = self._socket.recv(ctypes.sizeof(BlockDriverLayerTcp))
            tcp_header = BlockDriverLayerTcp.from_buffer_copy(pdu)
            tcp_length = tcp_header.tcp_length - ctypes.sizeof(BlockDriverLayerTcp)
            layers = CodeSysV3Protocol.parse_CodeSysTCPBlockDriverLayer(pdu + self._socket.recv(tcp_length))
        else:
            layers = CodeSysV3Protocol.parse_CodeSysDatagramLayer(self._socket.recvfrom(MAX_PDU_SIZE)[0])

        # Ignore Keep alive
        if len(layers) > 0 and isinstance(layers[-1], KeepLive):
            return self.recv_pdu()
        return layers

    def open_channel(self) -> CodeSysV3Channel:
        if not self.is_connected():
            raise CodeSysProtocolV3Exception("Device is not connected")
        self.logger.info("Opening a new channel with the device")
        self.send_pdu(DatagramLayerServices.ChannelManager,
                  CodeSysV3Protocol.build_CodeSysChannelLayerOpenRequest())
        layers = self.recv_pdu()
        if len(layers) > 0 and isinstance(layers[-1], OpenChannelResponse):
            return CodeSysV3Channel(layers[-1].channel_id, self)
        raise CodeSysProtocolV3Exception("Failed to open channel")

    def close_channel(self, channel_id):
        if not self.is_connected():
            raise CodeSysProtocolV3Exception("Device is not connected")
        self.logger.info(f"Closing a channel {channel_id: 04X}")
        self.send_pdu(DatagramLayerServices.ChannelManager,
                      CodeSysV3Protocol.build_CodeSysChannelLayerCloseChannel(channel_id))



    def _prepared_datagram_layer(self, service: DatagramLayerServices, payload: bytes):
        if self._datagram_type == DatagramLayerType.TCP:
            return CodeSysV3Protocol.build_DatagramLayerRequestOverTCP(self._src_ip, self._src_port,
                                                                       self._dst_ip, self._src_port, service, payload)
        elif self._datagram_type == DatagramLayerType.UDP:
            return CodeSysV3Protocol.build_DatagramLayerRequestOverUDP(self._src_ip, self._src_port,
                                                                             service, payload,
                                                                       dst_address=self._dst_address)

    def _get_dst_address(self):
        self.logger.info(f"Trying to receive the target device address: {self._dst_ip}")
        dst_address = None
        sock = None
        try:
            ns_server = CodeSysV3Protocol.build_NSServerDeviceInfo()
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            datagram = CodeSysV3Protocol.build_DatagramLayerRequestOverUDP(self._src_ip, CodeSysV3Device.UDP_PORT,
                                                                           DatagramLayerServices.NSServer, ns_server)
            sock.bind(('', CodeSysV3Device.UDP_PORT))
            sock.settimeout(5)

            sock.sendto(datagram, (self._dst_ip, CodeSysV3Device.UDP_PORT))
            response = sock.recvfrom(MAX_PDU_SIZE)[0]
            layers = CodeSysV3Protocol.parse_CodeSysDatagramLayer(response)
            if len(layers) > 0 and isinstance(layers[0], DatagramLayer):
                dst_address = layers[0].sender_address
        except Exception as ex:
            self.logger.error(f"Fail to get the target device address: {self._dst_ip}, Error: {ex}")
        finally:
            if sock is not None:
                sock.close()
        return dst_address

    def _determine_datagram_layer_type(self):
        self.logger.info(f"Trying to determine the datagram layer type to connect to {self._dst_ip}")
        self._dst_address = self._get_dst_address()
        if self._dst_address is not None:
            return DatagramLayerType.UDP
        elif self._check_for_datagram_layer_tcp():
            return DatagramLayerType.TCP

        raise CodeSysProtocolV3Exception("Couldn't figure out the Datagram layer type")

    def _check_for_datagram_layer_tcp(self):

        test_socket = None
        try:
            self.logger.info("Trying datagram layer TCP")
            ns_server = CodeSysV3Protocol.build_NSServerDeviceInfo()
            test_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            test_socket.bind(('', 0))
            test_socket.settimeout(5)
            src_port = test_socket.getsockname()[1]
            datagram = CodeSysV3Protocol.build_DatagramLayerRequestOverTCP(self._src_ip, src_port, self._dst_ip,
                                                                           CodeSysV3Device.TCP_PORT,
                                                                           DatagramLayerServices.NSServer, ns_server)
            test_socket.connect((self._dst_ip, CodeSysV3Device.TCP_PORT))
            test_socket.sendall(datagram)
            response = test_socket.recv(MAX_PDU_SIZE)
            layers = CodeSysV3Protocol.parse_CodeSysTCPBlockDriverLayer(response)
            if len(layers) > 0 and isinstance(layers[-1], NsClientDeviceInfo):
                self.logger.info("Succeeded to connect with TCP")
                return True
        except:
            pass
        finally:
            if test_socket:
                test_socket.close()
        self.logger.info("Failed to connect with TCP")
        return False

    def get_device_name_server_info(self) -> dict:
        if not self.is_connected():
            raise CodeSysProtocolV3Exception("Device is not connected")
        self.logger.info("Trying to read the device name server info")
        ns_server = CodeSysV3Protocol.build_NSServerDeviceInfo()
        self.send_pdu(DatagramLayerServices.NSServer, ns_server)
        pdu = self.recv_pdu()
        if len(pdu) > 0 and isinstance(pdu[-1], NsClientDeviceInfo):
            ns_client_info = pdu[-1]

            return {
                "node_name": ns_client_info.node_name,
                "device_name": ns_client_info.device_name,
                "vendor_name": ns_client_info.vendor_name,
                "firmware_str": ns_client_info.firmware_str,
            }

        return {}

    def send_channel_ack(self, channel_id: int, blk_id: int):
        if not self.is_connected():
            raise CodeSysProtocolV3Exception("Device is not connected")
        self.send_pdu(DatagramLayerServices.ChannelManager,
                      CodeSysV3Protocol.build_CodeSysChannelLayerAck(channel_id, blk_id))

    def read_over_channel(self, channel_id: int) -> typing.Tuple[ApplicationBlockFirst, typing.List[Tag], int]:
        if not self.is_connected():
            raise CodeSysProtocolV3Exception("Device is not connected")
        pdu = self.recv_pdu()
        while  len(pdu) > 0 and isinstance(pdu[-1], ApplicationAck):
            pdu = self.recv_pdu()
        tags = []
        last_blk_id = 0
        service_layer = None
        if len(pdu) > 1 and isinstance(pdu[-2], ApplicationBlockFirst):
            channel_layer = pdu[-2]
            service_layer_data = pdu[-1]
            last_blk_id = channel_layer.blk_id
            if channel_layer.channel_id == channel_id:
                # Check if it needs to be defragmented
                if channel_layer.remaining_data_size > len(service_layer_data):
                    self.send_channel_ack(channel_id, channel_layer.blk_id)
                    while len(service_layer_data) < channel_layer.remaining_data_size:
                        pdu = self.recv_pdu()
                        if len(pdu) > 1 and isinstance(pdu[-2], ApplicationBlock) and \
                            pdu[-2].channel_id == channel_id and pdu[-2].ack_id == channel_layer.ack_id \
                                and pdu[-2].blk_id >  last_blk_id:
                            self.send_channel_ack(channel_id, pdu[-2].blk_id)
                            service_layer_data += pdu[-1]
                            last_blk_id = pdu[-2].blk_id
                        else:
                            continue
                service_layer, tags = CodeSysV3Protocol.parse_CodeSysServiceLayer(service_layer_data)
        return service_layer, tags, last_blk_id

    def send_over_channel(self, channel_id: int, cmd_group: CmdGroup, smb_cmd: int, session_id: int,
                          blk_id: int, ack_id: int,
                          tags: typing.List[Tag] = None):
        if tags is None:
            tags = []
        if not self.is_connected():
            raise CodeSysProtocolV3Exception("Device is not connected")
        service_layer = CodeSysV3Protocol.build_CodeSysServicesLayer(cmd_group, smb_cmd, session_id, tags)
        channel_layer_pkts = CodeSysV3Protocol.build_CodeSysChannelLayerAppBlk(channel_id, blk_id, ack_id, service_layer)
        for pkt in channel_layer_pkts:
            self.send_pdu(DatagramLayerServices.ChannelManager, pkt)
        return len(channel_layer_pkts)
