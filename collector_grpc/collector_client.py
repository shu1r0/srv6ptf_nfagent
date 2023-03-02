import asyncio

import grpc

import packet_collector_pb2_grpc
from packet_collector_pb2 import PacketInfoStreamRequest


class NoChannelException(Exception):
    pass


class PacketCollectorClient:
    """Packet collector Client

    Attributes:
        ip (string) : target ip address
        port (int) : target port number
        channel : grpc channel
        stub : grpc service stub
    """

    def __init__(self, ip: str, port: str or int, node_id: int, node_id_length: int, counter_length: int, logger=None, event_loop=None):
        self.ip = ip
        self.port = port if isinstance(port, int) else int(port)
        self.node_id = node_id
        self.node_id_length = node_id_length
        self.counter_length = counter_length

        self.channel = None
        self.stub = None

        self.event_loop = event_loop if event_loop else asyncio.get_event_loop()

        self.packet_stream = None

        self.logger = logger

    def establish_channel(self):
        """establish grpc channel"""
        self.channel = grpc.aio.insecure_channel(self.ip + ':' + str(self.port), options=(('grpc.enable_http_proxy', 0),))
        self.stub = packet_collector_pb2_grpc.PacketCollectServiceStub(self.channel)

    def close_channel(self):
        """close channel"""
        if self.packet_stream:
            self.packet_stream.cancel()
        if self.channel:
            asyncio.ensure_future(self.channel.close(grace=None))

    def has_established_channel(self):
        """The client has established grpc channel"""
        return self.channel is not None and self.stub is not None

    async def notify_packet_info_coro(self, pkt_callback, pkt_id_callback, capture_all_packets=False, packet_max=-1):
        """notify packet to callback

        Args:
            callback (function) :
            packet_max (int) : max packet count
        """
        if not self.has_established_channel():
            raise NoChannelException
        req = PacketInfoStreamRequest()
        req.capture_all_packets = capture_all_packets
        req.node_id = self.node_id
        req.node_id_length = self.node_id_length
        req.counter_length = self.counter_length

        self.packet_stream = self.stub.GetPacketInfoStream(req)

        self.logger.debug("Send Notify Packet Info Request (node_id: {})".format(self.node_id))

        counter = 0
        try:
            async for p in self.packet_stream:
                if p.WhichOneof("data") == "packet":
                    p_d = {
                        "data": p.packet,
                        "node_id": p.node_id,
                        "timestamp": p.timestamp
                    }
                    if p.WhichOneof("metadata") == "netfilterInfo":
                        p_d["metadata"] = {
                            "netfilter_hook": p.netfilterInfo.hookpoint
                        }
                    elif p.WhichOneof("metadata") == "netfilterInfo":
                        p_d["metadata"] = {
                            "ebpf_hook": p.ebpfInfo.hookpoint
                        }
                    pkt_callback(p_d)
                elif p.WhichOneof("data") == "packet_id":
                    p_d = {
                        "pkt_id": p.packet_id,
                        "node_id": p.node_id,
                        "timestamp": p.timestamp
                    }
                    if p.WhichOneof("metadata") == "netfilterInfo":
                        p_d["metadata"] = {
                            "netfilter_hook": p.netfilterInfo
                        }
                    elif p.WhichOneof("metadata") == "netfilterInfo":
                        p_d["metadata"] = {
                            "ebpf_hook": p.ebpfInfo.hookpoint
                        }
                    pkt_id_callback(p_d)

                counter += 1
                if 0 < packet_max <= counter:
                    return
        except asyncio.CancelledError:
            self.logger.info("gRPC Stream Cancelled.")
