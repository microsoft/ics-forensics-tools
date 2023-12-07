from forensic.common.stream.stream import DataStruct, ubyte, dynamic, BinaryReader, uint16be, BinaryWriter

PARAM_CODE_TPDU_SIZE = 0xC0
PARAM_CODE_SRC_TSAP = 0xC1
PARAM_CODE_DST_TSAP = 0xC2

TPDU_TYPE_CONNECTION_REQUEST = 0xE0
TPDU_TYPE_CONNECTION_RESPONSE = 0xD0
TPDU_TYPE_DATA = 0xf0


class COTPLayer(DataStruct):
    size = ubyte
    tpdu = ubyte
    cotp_data = dynamic


class COTP_CR(DataStruct):
    dstref = uint16be
    srcref = uint16be
    flags = ubyte
    vars = dynamic


class COTP_DT(DataStruct):
    flags = ubyte
    tpdu_number = dynamic
    last_data_unit = dynamic


class COTPVars(DataStruct):
    src_tsap = dynamic
    dst_tsap = dynamic
    tpdu_size = dynamic


class COTP:
    def parse(self, br: BinaryReader) -> COTPLayer:
        res = COTPLayer(br)

        if res.tpdu == TPDU_TYPE_CONNECTION_RESPONSE:
            res.cotp_data = self.parse_connect(br)
        elif res.tpdu == TPDU_TYPE_DATA:
            res.cotp_data = self.parse_data(br)

        return res

    def parse_connect(self, br: BinaryReader) -> COTP_CR:
        res = COTP_CR(br)
        res.vars = self.parse_cotp_vars(br)

        return res

    def parse_cotp_vars(self, br: BinaryReader) -> COTPVars:
        res = COTPVars()

        while br.remaining_data() > 0:
            param_code = br.read(ubyte)

            if param_code == PARAM_CODE_SRC_TSAP:
                length = br.read(ubyte)

                if length == 2:
                    res.src_tsap = br.read(uint16be)
                else:
                    br.read_bytes(length)
            elif param_code == PARAM_CODE_DST_TSAP:
                length = br.read(ubyte)

                if length == 2:
                    res.dst_tsap = br.read(uint16be)
                else:
                    br.read_bytes(length)
            elif param_code == PARAM_CODE_TPDU_SIZE:
                length = br.read(ubyte)

                if length == 1:
                    res.tpdu_size = br.read(ubyte)
                else:
                    br.read_bytes(length)

        return res

    def parse_data(self, br: BinaryReader) -> COTP_DT:
        res = COTP_DT(br)
        res.tpdu_number = res.flags & 0x7F
        res.last_data_unit = bool(res.flags >> 7)

        return res

    def write_cr(self, dstref: int, srcref: int, src_tsap: int,
                 dst_tsap: int, tpdu_size: int = 0xa) -> BinaryWriter:
        bw_internal = BinaryWriter()
        bw_internal.write_struct(COTP_CR, {'dstref': dstref,
                                           'srcref': srcref,
                                           'flags': 0})

        bw_internal.write(ubyte, PARAM_CODE_SRC_TSAP)
        bw_internal.write(ubyte, 2)
        bw_internal.write(uint16be, src_tsap)

        bw_internal.write(ubyte, PARAM_CODE_DST_TSAP)
        bw_internal.write(ubyte, 2)
        bw_internal.write(uint16be, dst_tsap)

        bw_internal.write(ubyte, PARAM_CODE_TPDU_SIZE)
        bw_internal.write(ubyte, 1)
        bw_internal.write(ubyte, tpdu_size)

        bw = BinaryWriter()
        bw.write_struct(COTPLayer, {'size': len(bw_internal) + 1,
                                    'tpdu': TPDU_TYPE_CONNECTION_REQUEST})

        return bw + bw_internal

    def write_dt(self) -> BinaryWriter:
        bw = BinaryWriter()
        bw.write_struct(COTPLayer, {'size': 2,
                                    'tpdu': TPDU_TYPE_DATA})
        bw.write(ubyte, 0x80)

        return bw

    def write_dt_empty(self) -> BinaryWriter:
        bw = BinaryWriter()
        bw.write_struct(COTPLayer, {'size': 2,
                                    'tpdu': TPDU_TYPE_DATA})
        bw.write(ubyte, 0)

        return bw
