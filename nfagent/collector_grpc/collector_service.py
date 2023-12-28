import time
from packet_collector_pb2_grpc import PacketCollectServiceServicer
import nfagent.collector_grpc.packet_collector_pb2 as pb

from nfagent.mode import CollectMode


class PacketCollectService(PacketCollectServiceServicer):
    
    def __init__(self, logger):
        """init

        Args:
            logger (Logger): logger
        """
        self.logger = logger
        
        self._notify_packet_handler = None
        
    def set_notify_handler(self, handler):
        """Set handler when called remotely

        Args:
            handler  :
        """
        self._notify_packet_handler = handler

    def SetPoll(self, request, context):
        raise NotImplementedError()
    
    def GetPacketInfo(self, request, context):
        raise NotImplementedError()

    def GetEbpfProgramInfo(self, request, context):
        rep = pb.EbpfProgramInfoReply()
        print(request)
        return rep

    def GetPacketInfoStream(self, request, context):
        self.logger.debug("Notify Packet Info Called")
        if self._notify_packet_handler is None:
            raise Exception("Don't set notify_packet_handler")
        mode = CollectMode.PACKET if request.capture_all_packets else CollectMode.PACKET_ID
        queue = self._notify_packet_handler(mode=mode, node_id=request.node_id, node_id_length=request.node_id_length, counter_length=request.counter_length)
        while True:
            try:
                yield queue.get()
            except IndexError:
                time.sleep(0.1)
                pass

