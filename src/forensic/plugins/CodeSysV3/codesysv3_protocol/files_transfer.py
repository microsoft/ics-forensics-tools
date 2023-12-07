import logging
import pathlib
import typing
from .structures import *
from .channel import CodeSysV3Channel


class FilesTransfer:
    def __init__(self, channel: CodeSysV3Channel):
        self._channel = channel
        self.logger = logging.getLogger(self.__class__.__name__)

    def download(self, src_file: str, dst_file: pathlib.Path):

        if not self._channel.is_login:
            raise CodeSysProtocolV3Exception("Device is not connected")
        try:
            self.logger.info(f"Trying to download the file {src_file} over the channel {self._channel.channel_id: 04X}")
            src_file = bytes(src_file, "utf-8") + b"\x00"
            if len(src_file) < 14:
                src_file += b"\x00" * (len(src_file) - 14)

            if len(src_file) % 2 != 0:
                src_file += b"\x00"

            # Create Start download request
            self._channel.send(CmdGroup.CmpFileTransfer, 5, Tag(0x01, src_file), Tag(0x02, bytearray(8)))
            resp, tags = self._channel.read()

            error_code = tags[0x84][0x08].word
            if error_code == 0:
                full_file_path = str(tags[0x84][0x01].data, "utf-8")
                session_id = tags[0x84][0x03].dword
                file_size = int.from_bytes(tags[0x84][0x02].data[4:], "little")
                file_size_data = bytearray(12)
                file_size_data[:8] = tags[0x84][0x02].data
                file_size_data[0] = 1
                self.logger.info(f"Successfully open the file {full_file_path} over the channel {self._channel.channel_id: 04X}"
                                 f" to download, session ID: {session_id: 08X}, file size: {file_size} bytes")
                session_id = tags[0x84][0x03].data + b"\x00" * 4
                with dst_file.open("wb") as dst_fp:
                    written = 0
                    while written < file_size:
                        self._channel.send(CmdGroup.CmpFileTransfer, 7, Tag(0x05, session_id))
                        resp, tags = self._channel.read()
                        tag_data = tags.get(0x05, tags.get(0x07))
                        tag_size = tags[0x06].dword_le
                        if tag_size == 0:
                            break
                        if tag_data is None:
                            self.logger.error(f"Failed to download the file {src_file}, fail to get file's data")
                        dst_fp.write(tag_data.data)
                        written += len(tag_data.data)
                # Close the file
                self._channel.send(CmdGroup.CmpFileTransfer, 8, Tag(0x07, session_id + src_file),
                          Tag(0x02, file_size_data))
                layer, tags = self._channel.read()
            else:
                self.logger.error(f"Successfully open the file {src_file}, error_code:{error_code}")
        except Exception as ex:
            self.logger.error(f"Failed to download the file {src_file}, error: {ex}")

    def dir(self, folder: str):

        if not self._channel.is_login:
            raise CodeSysProtocolV3Exception("Device is not connected")
        try:
            self.logger.info(f"Trying to get folder list: {folder} over the channel {self._channel.channel_id: 04X}")
            folder = bytes(folder, "utf-8") + b"\x00"
            if len(folder) < 14:
                folder += b"\x00" * (len(folder) - 14)

            if len(folder) % 2 != 0:
                folder += b"\x00"

            self._channel.send(CmdGroup.CmpFileTransfer, 12, Tag(0x0b, folder))
            resp, tags = self._channel.read()
            files = tags[0x8d][0x90]
            dir_files = []
            for f in files:
                if f[0x0e] is not None:
                    dir_files.append(str(f[0x0e].data, "utf-8").replace("\0", ""))
            return dir_files
        except Exception as ex:
            self.logger.error(f"Failed to get folder list {folder}, error: {ex}")


