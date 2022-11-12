import asyncio
import time
from logging import INFO, DEBUG, getLogger
import argparse

from collector_grpc.collector_client import PacketCollectorClient
from utils.log import get_stream_handler, get_file_handler
from mode import CollectMode


class CollectorNode(PacketCollectorClient):
    """Node for Collector"""

    def __init__(self, name, ip, port, node_id, node_id_length, counter_length, event_loop=None, logger=None):
        logger = logger if logger else getLogger(__name__)
        super(CollectorNode, self).__init__(ip, port, node_id, node_id_length, counter_length, logger, event_loop=event_loop)
        self.name = name

    def __eq__(self, other):
        if not isinstance(other, CollectorNode):
            return False
        if self.name == other.name:
            return True
        else:
            return False

    def __int__(self):
        return self.node_id

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<CollectorNode name={} ip={} port={} node_id={}>".format(self.name, self.ip, self.port, self.node_id)


class Collector:
    """Packet Collecot"""

    def __init__(self, node_id_length=16, counter_length=32, logger=None):
        self.nodes: list[CollectorNode] = []
        self.logger = logger if logger else getLogger(__name__)

        self.node_id_length = node_id_length
        self.counter_length = counter_length

        self.event_loop = asyncio.get_event_loop()

        self._notify_packet_tasks = None

        # callback
        self._packet_update_callback = None
        self._packet_id_update_callback = None

    def add_node(self, name, ip, port, node_id):
        """add SRv6 Node

        Args:
            name (str) : node name
            ip (str) : node ip address
            port (str or int) : node port number
            node_id (int) : node identifier

        Returns:
            SRv6Node
        """
        node = CollectorNode(name, ip, port, node_id, self.node_id_length, self.counter_length,
                             event_loop=self.event_loop, logger=self.logger)
        if node not in self.nodes:
            self.nodes.append(node)
            self.logger.debug("Node {} is added.".format(name))
        return node

    def get(self, node):
        """get SRv6 Node

        Args:
            node (str or int) : node_name or node_id

        Returns:
            Node or None
        """
        if isinstance(node, CollectorNode):
            node = node.name
        if isinstance(node, str):
            for n in self.nodes:
                if node == n.name:
                    return n
        if isinstance(node, int):
            for n in self.nodes:
                if node == n.node_id:
                    return n
        return None

    def connect(self, name):
        """connect to node

        Args:
            name (str) :
        """
        self.logger.info("gRPC client connect to server (ip={}, port={})".format(self.get(name).ip, self.get(name).port))
        node = self.get(name)
        node.establish_channel()

    def is_connected(self, name):
        """Is connected to the node

        Args:
            name (str) :

        Returns:
            bool
        """
        return self.get(name).has_established_channel()

    def connect_all(self):
        """connect all node"""
        for node in self.nodes:
            if not self.is_connected(node.name):
                self.connect(node.name)

    def close_all(self):
        """close all channel"""
        self.logger.info("close all channel")
        for node in self.nodes:
            node.close_channel()

    def start(self, mode=CollectMode.PACKET, timeout=None):
        """start collector

        Args:
            timeout (int) : collector timeout. This time may be used for debugging.
        """
        asyncio.set_event_loop(self.event_loop)
        self.logger.info("start collector (nodes = {} mode={})".format(self.nodes, mode.name))

        self.connect_all()

        assert self._packet_update_callback is not None
        assert self._packet_id_update_callback is not None
        capture_all_packets = True if mode == CollectMode.PACKET else False
        self._notify_packet_tasks = self._set_notify_packet_info_coro(capture_all_packets=capture_all_packets)

        if timeout:
            self.event_loop.run_until_complete(
                asyncio.wait_for(self._notify_packet_tasks, loop=self.event_loop, timeout=timeout)
            )
        else:
            self.event_loop.run_forever()

    def stop(self):
        """event_loop stop and close all channel"""
        self._notify_packet_tasks.cancel()
        self.close_all()
        if self.event_loop.is_running():
            asyncio.ensure_future(self.event_loop.shutdown_asyncgens(), loop=self.event_loop)
        else:
            self.event_loop.run_until_complete(self.event_loop.shutdown_asyncgens())
        self.event_loop.call_soon_threadsafe(self.event_loop.stop)
        time.sleep(0.5)
        self.event_loop.call_soon_threadsafe(self.event_loop.close)

    def _set_notify_packet_info_coro(self, capture_all_packets=False):
        coros = []
        for n in self.nodes:
            coros.append(n.notify_packet_info_coro(self._packet_update_callback, self._packet_id_update_callback, capture_all_packets=capture_all_packets))
        return asyncio.gather(*coros)

    def _notify_packet_callback(self, packet):
        if self._packet_update_callback is None:
            raise Exception("packet_update_callback not set")
        self._packet_update_callback(packet)

    def set_packet_update(self, func):
        """set packet update callback"""
        self._packet_update_callback = func

    def set_packet_id_update(self, func):
        """set packet update callback"""
        self._packet_id_update_callback = func


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--log_file', help="log file path")

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()
    log_level = DEBUG if args.verbose else INFO
    log_file = args.log_file

    logger = getLogger(__name__)
    logger.setLevel(log_level)
    logger.addHandler(get_stream_handler(log_level))
    if log_file:
        logger.addHandler(get_file_handler(log_file, log_level))

    def print_pkt(p):
        print(p)

    controller = Collector(logger=logger)
    controller.set_packet_update(print_pkt)
    controller.start()
