#!/usr/bin/env python3


import asyncio
import functools
import subprocess
from logging import getLogger, INFO, DEBUG
import argparse
from datetime import datetime
from concurrent import futures
# from faster_fifo import Queue
# import faster_fifo_reduction
from collections import deque

import grpc
from netfilterqueue import NetfilterQueue, Packet

from nfagent.collector_grpc.packet_collector_pb2_grpc import add_PacketCollectServiceServicer_to_server
import nfagent.collector_grpc.packet_collector_pb2 as pb

from nfagent.mode import CollectMode, str2mode
from nfagent.collector_grpc.collector_service import PacketCollectService
from nfagent.packet_id_setter import PktIdTLVSetter, Hook, PktIdTLVSetterSRH
from nfagent.utils.log import get_file_handler, get_stream_handler


class CircularBuffer(deque):

    def __init__(self, maxsize):
        super(CircularBuffer, self).__init__(maxlen=maxsize)

    def put(self, item):
        self.append(item)

    def get(self):
        return self.popleft()


class PacketCollectorAgent:
    """Packet Collector Agent

    Attributes:
        service (PacketCollectService) : gRPC SRv6 Service
        server (grpc.Server) : gRPC server
        ip (str) : server ip address
        port (str) : listening port
        logger (Logger) : logger
    """

    def __init__(self, nfqueue_num_pre, nfqueue_num_post, ip, port, log_level=INFO, event_loop=None, log_file=None, pktid_setter_cls=PktIdTLVSetterSRH):
        # set logger
        self.logger = getLogger(__name__)
        self.logger.setLevel(log_level)
        self.logger.addHandler(get_stream_handler(log_level))
        if log_file:
            self.logger.addHandler(get_file_handler(log_file, log_level))

        # prepare netfilter queue
        self.nfqueue_pre = NetfilterQueue()
        self.nfqueue_post = NetfilterQueue()
        self.nfqueue_num_pre = nfqueue_num_pre if isinstance(nfqueue_num_pre, int) else int(nfqueue_num_pre)
        self.nfqueue_num_post = nfqueue_num_post if isinstance(nfqueue_num_post, int) else int(nfqueue_num_post)
        
        self.service = PacketCollectService(logger=self.logger)
        self.service.set_notify_handler(self.notify_handler)

        self.event_loop = event_loop if event_loop else asyncio.get_event_loop()
        
        self.server = None
        self.ip = ip
        self.port = port

        self.pktid_setter_cls = pktid_setter_cls
        self.pktid_setter = None

        self._packet_queue_size = 2**16
        self._packet_queue = CircularBuffer(self._packet_queue_size)
        self._collect_mode: CollectMode = None

        self.nf_fd_pre = None
        self.nf_fd_post = None
    
    def __del__(self):
        self.stop()

    @property
    def packet_queue(self):
        return self._packet_queue

    def start(self):
        """start server"""
        self.logger.info("server start (ip={}, port={})".format(self.ip, self.port))

        # start grpc server
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        add_PacketCollectServiceServicer_to_server(
            self.service, self.server
        )
        self.server.add_insecure_port(self.ip + ':' + self.port)
        self.server.start()

        # bind netfilter queue
        self.nfqueue_pre.bind(self.nfqueue_num_pre, self.nfqueue_callback, max_len=2**32-1)
        self.nfqueue_post.bind(self.nfqueue_num_post, self.nfqueue_callback, max_len=2**32-1)

        # set asyncio
        self.nf_fd_pre = self.nfqueue_pre.get_fd()
        self.nf_fd_post = self.nfqueue_post.get_fd()
        callback_pre = functools.partial(self.nfqueue_pre.run, block=False)
        callback_post = functools.partial(self.nfqueue_post.run, block=False)
        self.event_loop.add_reader(self.nf_fd_pre, callback_pre)
        self.event_loop.add_reader(self.nf_fd_post, callback_post)

        # run event loop
        self.event_loop.run_forever()

    def stop(self):
        """stop server"""
        self.logger.info("server stop (ip={}, port={})".format(self.ip, self.port))
        if self.server:
            self.server.stop(grace=None)

        self.event_loop.remove_reader(self.nf_fd_pre)
        self.event_loop.remove_reader(self.nf_fd_post)
        self.nfqueue_post.unbind()
        self.nfqueue_pre.unbind()

        self.event_loop.stop()
            
    def notify_handler(self, mode, node_id, node_id_length, counter_length) -> CircularBuffer:
        """called by gRPC Service"""
        self._collect_mode = mode
        self.pktid_setter = self.pktid_setter_cls(node_id=node_id, node_id_length=node_id_length, counter_length=counter_length)
        return self._packet_queue

    def nfqueue_callback(self, pkt: Packet):
        """call back for nfqueue"""
        if self.pktid_setter:
            payload, pkt_id, send_flag = self.pktid_setter.set_tlv(pkt.get_payload(), pkt.hook)
            pkt.set_payload(payload)
            if send_flag and self._packet_queue is not None:
                pktinfo_buf = pb.PacketInfo()
                if self._collect_mode == CollectMode.PACKET:
                    pktinfo_buf.packet = payload
                elif self._collect_mode == CollectMode.PACKET_ID:
                    if pkt.hook == Hook.PREROUTING:
                        pktinfo_buf.packet_id = pkt_id
                    elif pkt.hook == Hook.POSTROUTING:
                        pktinfo_buf.packet = payload
                pktinfo_buf.node_id = self.pktid_setter.node_id
                pktinfo_buf.timestamp = datetime.now().timestamp()
                netf_info = pb.NetFilterInfo()
                netf_info.hookpoint = Hook(pkt.hook).name
                pktinfo_buf.netfilterInfo.CopyFrom(netf_info)
                pktinfo_buf.packet_protocol = pb.PacketProtocol.PROTOCOL_IPV6
                pktinfo_buf.pktid_exthdr = pb.PktIdExtHdr.EXTHDR_ROUTING
                self._packet_queue.put(pktinfo_buf)

            self.logger.debug("packet payload after set_tlv. hook={}, send_flag={} : {}".format(pkt.hook, send_flag, payload))

        pkt.accept()


def get_args():
    """get args from command line"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-f', '--force_pktid_setting', action='store_true')
    parser.add_argument('--log_file', help="log file path")

    parser.add_argument('--ip', help='server ip address', default="[::]")
    parser.add_argument('--port', help='listening port', default="31000")
    
    parser.add_argument('--nfqueue_num_pre', help='nfqueue number (PREROUTING)', default=1)
    parser.add_argument('--nfqueue_num_post', help='nfqueue number (POSTROUTING)', default=10)
    
    parser.add_argument('-s', '--stand_alone', help="run stand alone", action='store_true')
    parser.add_argument('-m', '--mode', help='packet or packet_id (only stand alone mode)', default="packet_id")
    parser.add_argument('--node_id', help='node id (only stand alone mode)', default=1)
    parser.add_argument('--node_id_length', help='node id length (only stand alone mode)', default=16)
    parser.add_argument('--counter_length', help='counter length (only stand alone mode)', default=32)

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()
    if args.verbose:
        log_level = DEBUG
    else:
        log_level = INFO
    log_file = args.log_file

    ip = args.ip
    port = args.port
    
    nfqueue_num_pre = args.nfqueue_num_pre
    nfqueue_num_post = args.nfqueue_num_post
    
    # set ip6tables
    prerouting_cmd = "ip6tables -t mangle -m ipv6header --soft --header ipv6-route -I PREROUTING -j NFQUEUE --queue-num %d" % nfqueue_num_pre
    postrouting_cmd = "ip6tables -t mangle -m ipv6header --soft --header ipv6-route -I POSTROUTING -j NFQUEUE --queue-num %d" % nfqueue_num_post
    r = subprocess.run(prerouting_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(r.stdout)
    proc = subprocess.run(postrouting_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(r.stdout)

    agent = PacketCollectorAgent(nfqueue_num_pre=nfqueue_num_pre, nfqueue_num_post=nfqueue_num_post,
                                 ip=ip, port=port, log_level=log_level, log_file=log_file)
    if args.stand_alone:
        mode = str2mode(args.mode)
        agent.notify_handler(mode=mode, node_id=int(args.node_id), node_id_length=int(args.node_id_length), counter_length=int(args.counter_length))
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
        if args.stand_alone:
            print(agent.packet_queue)

