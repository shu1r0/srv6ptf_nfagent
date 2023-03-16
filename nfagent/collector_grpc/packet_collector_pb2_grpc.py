# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import packet_collector_pb2 as packet__collector__pb2


class PacketCollectServiceStub(object):
    """*
    Packet Collector
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SetPoll = channel.unary_unary(
                '/PacketCollectService/SetPoll',
                request_serializer=packet__collector__pb2.PollSettingRequest.SerializeToString,
                response_deserializer=packet__collector__pb2.PollSettingReply.FromString,
                )
        self.GetPacketInfo = channel.unary_unary(
                '/PacketCollectService/GetPacketInfo',
                request_serializer=packet__collector__pb2.PacketInfoRequest.SerializeToString,
                response_deserializer=packet__collector__pb2.PacketInfoReply.FromString,
                )
        self.GetPacketInfoStream = channel.unary_stream(
                '/PacketCollectService/GetPacketInfoStream',
                request_serializer=packet__collector__pb2.PacketInfoStreamRequest.SerializeToString,
                response_deserializer=packet__collector__pb2.PacketInfo.FromString,
                )


class PacketCollectServiceServicer(object):
    """*
    Packet Collector
    """

    def SetPoll(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetPacketInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetPacketInfoStream(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_PacketCollectServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SetPoll': grpc.unary_unary_rpc_method_handler(
                    servicer.SetPoll,
                    request_deserializer=packet__collector__pb2.PollSettingRequest.FromString,
                    response_serializer=packet__collector__pb2.PollSettingReply.SerializeToString,
            ),
            'GetPacketInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.GetPacketInfo,
                    request_deserializer=packet__collector__pb2.PacketInfoRequest.FromString,
                    response_serializer=packet__collector__pb2.PacketInfoReply.SerializeToString,
            ),
            'GetPacketInfoStream': grpc.unary_stream_rpc_method_handler(
                    servicer.GetPacketInfoStream,
                    request_deserializer=packet__collector__pb2.PacketInfoStreamRequest.FromString,
                    response_serializer=packet__collector__pb2.PacketInfo.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'PacketCollectService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class PacketCollectService(object):
    """*
    Packet Collector
    """

    @staticmethod
    def SetPoll(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/PacketCollectService/SetPoll',
            packet__collector__pb2.PollSettingRequest.SerializeToString,
            packet__collector__pb2.PollSettingReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetPacketInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/PacketCollectService/GetPacketInfo',
            packet__collector__pb2.PacketInfoRequest.SerializeToString,
            packet__collector__pb2.PacketInfoReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetPacketInfoStream(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/PacketCollectService/GetPacketInfoStream',
            packet__collector__pb2.PacketInfoStreamRequest.SerializeToString,
            packet__collector__pb2.PacketInfo.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)