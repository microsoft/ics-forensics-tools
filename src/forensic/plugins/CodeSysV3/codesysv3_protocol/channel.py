import logging
import pathlib
from .device import *
from .encryption import CodeSysV3Encryption


class CodeSysV3Channel:

    def __init__(self, channel_id, device):
        self._device = device
        self._channel_id = channel_id
        self._ack_id = 0
        self._blk_id = 1
        self._session_id = 0
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def is_login(self):
        return self._session_id != 0

    @property
    def channel_id(self):
        return self._channel_id

    @property
    def session_id(self):
        return self._session_id

    def send(self, cmd_group: CmdGroup, smb_cmd: int, *tags: Tag):
        if tags is None:
            tags = []
        self._blk_id += self._device.send_over_channel(self._channel_id, cmd_group, smb_cmd, self._session_id, self._blk_id,
                                       self._ack_id, tags)

    def read(self) -> typing.Tuple[ServiceLayer, typing.Dict[int, Tag]]:
        service_layer, tags, ack_id = self._device.read_over_channel(self._channel_id)
        if service_layer is None:
            raise CodeSysProtocolV3Exception("Fail to read from channel")
        self._device.send_channel_ack(self._channel_id, ack_id)
        self._ack_id = ack_id

        return service_layer, tags

    def close(self):
        self.logger.info(f"Closing the channel {self._channel_id:04X}")
        self._device.close_channel(self._channel_id)

    def login(self, username: str = "", password: str = "") -> bool:
        self.logger.info(f"Trying to login over the channel {self._channel_id: 04X}")
        try:
            tags = []
            if len(username) % 2 != 0:
                username += '\0'
            tags.append(Tag(0x22, b"\x01\x00\x00\x00"))
            if len(password) > 0:
                password_hash = CodeSysV3Encryption.hash_password(CodeSysV3Encryption.CHALLENGE, password)
                tags.append(Tag(0x23, CodeSysV3Encryption.CHALLENGE.to_bytes(4, "little")))
                username_pass_tag = Tag(0x81)
                tags.append(username_pass_tag)
                username_pass_tag.add_tag(Tag(0x10, bytes(username, "ascii"), align=0x42))
                username_pass_tag.add_tag(Tag(0x11, password_hash))
            else:
                username_pass_tag = Tag(0x81)
                tags.append(username_pass_tag)
                username_pass_tag.add_tag(Tag(0x10, bytes(username, "ascii"), align=0x40))
            self.send(CmdGroup.CmpDevice, 2, *tags)
            service_layer, tags  = self.read()
            if service_layer is not None and len(tags) > 0 and service_layer.cmd_group == CmdGroup.CmpDevice.value and service_layer.subcmd == 2:
                session_id = tags[0x82].get_tag(0x21)
                if session_id is not None:
                    self._session_id = session_id.dword_le
                    self.logger.info(f"Login successfully to the device, session id: {self._session_id: 08X}")
                    return True

                else:
                    self.logger.error(f"Failed to login to the device, error_code: {tags[0x82][0x20].word: 04X}")
        except Exception as ex:
            self.logger.error(f"Failed to login to the device, error: {ex}")
        return False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()