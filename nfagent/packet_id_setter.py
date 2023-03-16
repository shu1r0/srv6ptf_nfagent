from enum import Enum, IntEnum
from struct import Struct
from typing import Tuple, Optional


IPV6_HEADER_LENGTH = 40

ETH_TYPE_IPV6 = 0x86dd
IPV6_NEXT_HEADER_ROUTING_HEADER = 43

ehternet_struct = Struct("! 6s 6s H")

# Structure
#  * 4s : (bytes) Version ~ FlowLabel
#  * H : (int) Payload Length
#  * B : (int) Next Header
#  * B : (int) Hop Limit
#  * 16s : (bytes) Source Address
#  * 16s : (bytes) Destination Address
ipv6header_struct = Struct("! 4s H B B 16s 16s")

srh_struct_no_segmentlist = Struct("! B B B B B B H")


class SRHStruct:
    
    LENGTH_NO_SEGMENTLIST = 8  # (bytes)
    SEGMENT_LENGTH = 16  # (bytes)
    
    def __init__(self):
        self.next_header = 0
        # worning 8 bytes octet
        self.hdr_ext_len = 0
        self.routing_type = 0
        self.segments_left = 0
        self.last_entry = 0
        self.flags = 0
        self.tag = 0
        self.segment_list = b''
        self.tlv_objects = b''
        
        self.payload = b''
    
    def unpack(self, data: bytes):
        data_no_segmentlist = data[:SRHStruct.LENGTH_NO_SEGMENTLIST]
        (self.next_header, self.hdr_ext_len, self.routing_type, self.segments_left, self.last_entry, self.flags, self.tag) = srh_struct_no_segmentlist.unpack(data_no_segmentlist)

        segment_list_length = SRHStruct.SEGMENT_LENGTH*(self.last_entry+1)
        self.segment_list = data[SRHStruct.LENGTH_NO_SEGMENTLIST:SRHStruct.LENGTH_NO_SEGMENTLIST+segment_list_length]

        srh_length = SRHStruct.LENGTH_NO_SEGMENTLIST+self.hdr_ext_len*8
        tlv_data = data[SRHStruct.LENGTH_NO_SEGMENTLIST+segment_list_length:srh_length]
        self.tlv_objects = tlv_data

        self.payload = data[srh_length:]
    
    def pack(self) -> bytes:
        srh_header = srh_struct_no_segmentlist.pack(
            self.next_header, self.hdr_ext_len, self.routing_type, self.segments_left, self.last_entry,
            self.flags, self.tag
        )
        return srh_header + self.segment_list + self.tlv_objects + self.payload
    
    def add_tlv(self, tlv: bytes, append_hdr_len: int):
        self.tlv_objects = tlv + self.tlv_objects
        self.hdr_ext_len += append_hdr_len
    
    def has_tlv(self, type: int) -> bool:
        if len(self.tlv_objects) > 0:
            for tlv in self.parse_tlv(self.tlv_objects):
                if not isinstance(tlv, tuple):
                    return tlv == type
                if type == tlv[0]:
                    return True
        return False

    def get_tlv_value(self, type: int) -> Optional[bytes]:
        if len(self.tlv_objects) > 0:
            parsed_result = self.parse_tlv(self.tlv_objects)
            for tlv in parsed_result:
                if not isinstance(tlv, tuple):
                    if tlv == type:
                        return parsed_result[2]
                if type == tlv[0]:
                    return tlv[2]
        return None

    @classmethod
    def parse_tlv(cls, tlvs: bytes):
        tlv_header_struct = Struct("! B B")
        tlv_header = tlvs[:2]
        tlv_type, tlv_length = tlv_header_struct.unpack(tlv_header)
        rest = tlvs[2:]
        tlv_value = rest[:tlv_length]
        rest = rest[tlv_length:]
        tlv = (tlv_type, tlv_length, tlv_value)
        if len(rest) > 0:
            return tlv, cls.parse_tlv(rest)
        else:
            return tlv


class Hook(IntEnum):
    
    PREROUTING = 0
    INPUT = 1
    FORWARD = 2
    OUTPUT = 3
    POSTROUTING = 4


class PktIdTLVSetter:
    
    PKTIDTLV_TYPE = 124
    PKTIDTLV_TYPE_BYTES = PKTIDTLV_TYPE.to_bytes(1, "big")
    
    def __init__(self, node_id: int, node_id_length: int, counter_length: int):
        """

        Args:
            node_id (int): node is
            node_id_length (int): node id length (bit)
            counter_length (int): counter length (bit)
        """
        assert len(format(node_id, 'b')) <= node_id_length 
        assert (node_id_length + counter_length) % 8 == 0
        
        self.node_id = node_id
        self.node_id_length = node_id_length
        self.counter = 0
        self.counter_length = counter_length

    @property
    def type(self) -> bytes:
        return self.PKTIDTLV_TYPE_BYTES

    @property
    def value_length(self) -> int:
        return (self.node_id_length + self.counter_length) // 8

    @property
    def tlv_length(self) -> int:
        return self.value_length + 1 + 1
    
    @property
    def value(self) -> bytes:
        return self.node_id.to_bytes(self.node_id_length // 8, "big") + self.counter.to_bytes(self.counter_length // 8, "big")
    
    @property
    def tlv_obj(self) -> bytes:
        return self.type + self.value_length.to_bytes(1, "big") + self.value

    def set_tlv(self, pkt: bytes, hook: int) -> Tuple[bytes, int, bool]:
        """set pktid tlv object to packet

        Args:
            pkt (bytes): packet
            hook (int): nfqueue hook point

        Returns:
            Tuple(bytes, int, bool): packet and send_flag. If send_flag is True, the packet is sent.
        """
        send_flag = False
        ipv6_header = list(ipv6header_struct.unpack(pkt[:IPV6_HEADER_LENGTH]))
        rest_pkt = pkt[IPV6_HEADER_LENGTH:]
        if ipv6_header[2] == IPV6_NEXT_HEADER_ROUTING_HEADER:
            srh = SRHStruct()
            srh.unpack(rest_pkt)

            tlv_value = srh.get_tlv_value(self.PKTIDTLV_TYPE)
            if tlv_value:
                if hook == Hook.PREROUTING:
                    pkt_id = int.from_bytes(tlv_value, "big")
                    send_flag = True
                    return pkt, pkt_id, send_flag
            else:
                pkt_id = int.from_bytes(self.value, "big")
                srh.add_tlv(self.tlv_obj, self.tlv_length // 8)
                self.counter += 1
                ipv6_header[1] += self.tlv_length

                pkt = ipv6header_struct.pack(*ipv6_header) + srh.pack()
                send_flag = True
                return pkt, pkt_id, send_flag

        return pkt, -1, send_flag

