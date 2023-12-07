import socket
from typing import List
from forensic.plugins.s7.cotp import COTP, COTP_DT, COTPLayer, COTP_CR
from forensic.plugins.s7.s7_parser import (S7ListBlocksEntry, S7ListBlocksOfTypeEntry, S7Parser, S7LayerResponse,
                                           NOT_LAST_DATA_UNIT, S7Error, S7ErrorNotPermitted, NO_ERROR)
from forensic.plugins.s7.tpkt import TPKT, TPKTLayer
from forensic.common.stream.stream import (BinaryWriter, BinaryReader, DataStruct, StreamNotEnoughData)


class InvalidS7RackSlot(Exception):
    pass

class S7Conn(object):
    def __init__(self, logger, ip: str, port: int = 102, rack: int = 0, slot: int = 0, timeout=20) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ip = ip
        self._port = port
        self._s7_parser = S7Parser()
        self._rack = rack
        self._slot = slot
        self.logger = logger
        self._sock.settimeout(timeout)

    def __enter__(self):
        self._sock.connect((self._ip, self._port))
        self.create_session(self._rack, self._slot)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._sock.close()

    def create_session(self, rack: int = 0, slot: int = 0):
        data = TPKT().write(3, COTP().write_cr(0, 0x14, 0x100, 0x100 + (rack * 0x20) + slot)).dump()
        self._sock.sendall(data)

        try:
            cotp = self.parse_cotp(BinaryReader(self._sock.recv(1024)))
        except ConnectionResetError:
            raise InvalidS7RackSlot()

        if cotp is None:
            raise InvalidS7RackSlot()

        if isinstance(cotp.cotp_data, COTP_CR) and cotp.cotp_data.flags == 0:
            self.setup_communication()

    def parse_cotp(self, br: BinaryReader, is_recurse: bool = False) -> [COTPLayer, BinaryReader]:
        cotp = None

        if br.remaining_data() > TPKTLayer.get_size():
            tpkt = TPKT().parse(br)

            if tpkt.real_length > COTPLayer.get_size():
                cotp = COTP().parse(br)

                # Not last data unit
                if isinstance(cotp.cotp_data, COTP_DT) and cotp.cotp_data.last_data_unit == 0:
                    if tpkt.length > 7:
                        # TODO: COTP_DT data layer aggregation
                        pass
                    else:
                        # Avoid endless recurse, do it just once, otherwise drop it...
                        if not is_recurse:
                            cotp = self.parse_cotp(br, is_recurse=True)

        return cotp

    def parse_s7(self, cotp: COTPLayer, br: BinaryReader) -> S7LayerResponse:
        s7layer = None

        if br.remaining_data() > 0 and isinstance(cotp.cotp_data, COTP_DT):
            try:
                s7layer = self._s7_parser.parse(br)
            except StreamNotEnoughData:
                self.logger.warning(f'Stream not enough data for IP: {self._ip}, '
                                    f'Port: {self._port}, Rack: {self._rack}, Slot: {self._slot}')

        return s7layer

    def _send_ack(self):
        self._sock.sendall(TPKT().write(3, COTP().write_dt_empty()).dump())

    def _req_rep(self, bw_data: BinaryWriter) -> S7LayerResponse:
        data = TPKT().write(3, COTP().write_dt() + bw_data).dump()
        self._sock.sendall(data)

        is_emnpty_cotp_ack = True

        while is_emnpty_cotp_ack:
            br = BinaryReader(self._sock.recv(4096))
            cotp = self.parse_cotp(br)

            if br.remaining_data() > 0:
                is_emnpty_cotp_ack = False

        self._send_ack()
        return self.parse_s7(cotp, br)

    def setup_communication(self):
        return self._req_rep(self._s7_parser.write_setup_communication())

    def read_szl(self, szl_id: int, szl_index: int = 0) -> List[DataStruct]:
        response = self._req_rep(self._s7_parser.write_read_szl(szl_id, szl_index))

        n_limit = 20
        while response is not None and response.param.last_data_unit == NOT_LAST_DATA_UNIT \
                and response.param.sequence_num != 0 and n_limit > 0:
            response = self._req_rep(self._s7_parser.write_read_szl(szl_id, szl_index, response.param.sequence_num))
            n_limit -= 1

        return response if response is None else response.data.szl_list

    def list_blocks(self) -> List[S7ListBlocksEntry]:
        response = self._req_rep(self._s7_parser.write_list_blocks())

        n_limit = 20
        while response is not None and response.param.last_data_unit == NOT_LAST_DATA_UNIT \
                and response.param.sequence_num != 0 and n_limit > 0:
            response = self._req_rep(self._s7_parser.write_list_blocks(response.param.sequence_num))
            n_limit -= 1

        return [] if (response is None or response.data is None) else response.data.entries

    def list_blocks_of_type(self, block_type: str) -> List[S7ListBlocksOfTypeEntry]:
        response = self._req_rep(self._s7_parser.write_list_blocks_of_type(block_type))

        n_limit = 20
        while response is not None and response.param.last_data_unit == NOT_LAST_DATA_UNIT \
                and response.param.sequence_num != 0 and n_limit > 0:
            response = self._req_rep(self._s7_parser.write_list_blocks_of_type(block_type, response.param.sequence_num))
            n_limit -= 1

        return [] if (response is None or response.data is None) else response.data.entries

    def blocks(self):
        res = []

        try:
            for block_count_entry in self.list_blocks():
                if block_count_entry.block_count > 0:
                    try:
                        for block_entry in self.list_blocks_of_type(block_count_entry.block_type):
                            res.append({'type': block_count_entry.block_type, 'language': block_entry.block_lang,
                                        'num': block_entry.block_number, 'flags': block_entry.block_flags})
                    except S7Error:
                        self.logger.warning(f'S7 client blocks error for IP: {self._ip}, '
                                            f'Port: {self._port}, Rack: {self._rack}, Slot: {self._slot}')

        except S7Error:
            self.logger.warning(f'S7 client blocks error for IP: {self._ip}, '
                                f'Port: {self._port}, Rack: {self._rack}, Slot: {self._slot}')

        return res

    def _start_upload(self, block_type, block_num) -> S7LayerResponse:
        return self._req_rep(self._s7_parser.write_start_upload(block_type, block_num))

    def _upload(self, upload_id: int) -> S7LayerResponse:
        return self._req_rep(self._s7_parser.write_upload(upload_id))

    def _end_upload(self, upload_id: int) -> S7LayerResponse:
        return self._req_rep(self._s7_parser.write_end_upload(upload_id))

    def upload_block(self, block: dict) -> bytes:
        start_upload = self._start_upload(block['type'], block['num'])
        block_data = None

        if start_upload.error == NO_ERROR:
            upload_id = start_upload.param.upload_id
            upload = self._upload(upload_id)
            block_data = upload.param.data

            while upload.param.status == NOT_LAST_DATA_UNIT:
                upload = self._upload(upload_id)
                block_data += upload.param.data

            self._end_upload(upload_id)

        return block_data

    def upload_all_blocks(self):
        all_blocks = {}

        for block in self.blocks():
            block['protected'] = False

            for _ in range(5):
                try:
                    block['data'] = self.upload_block(block)
                except S7ErrorNotPermitted:
                    block['protected'] = True
                except Exception as e:
                    self.logger.warning(f'Upload all blocks exception {e} for IP: {self._ip}, '
                                        f'Port: {self._port}, Rack: {self._rack}, Slot: {self._slot}')

                    continue
                break

            all_blocks[f'{block["type"]}{block["num"]}'] = block

        return all_blocks

    def dump_plc(self):
        res = None

        try:
            szl_0_res = self.read_szl(0)
        except S7Error:
            szl_0_res = None

        if szl_0_res:
            res = {'rack': self._rack, 'slot': self._slot, 'supported_szl': list(map(lambda x: x.szl_id, szl_0_res)), 'szl': dict()}
            for szl in [0x11, 0x424, 0x1c]:
                if szl in res['supported_szl']:
                    try:
                        if szl_res := self.read_szl(szl):
                            res['szl']['szl_%04X' % szl] = szl_res
                    except S7Error:
                        pass

            for szl, index in [(0x31, 3), (0x32, 4)]:
                if szl in res['supported_szl']:
                    try:
                        if szl_res := self.read_szl(szl, index):
                            res['szl'][f'szl_%04X_%04X' % (szl, index)] = szl_res
                    except S7Error:
                        pass

            if block_res := self.upload_all_blocks():
                res['blocks'] = block_res

        return res
