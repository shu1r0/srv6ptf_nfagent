#!/bin/bash

IP="[::]"
PORT=31000

QUEUE_NUM_PREROUTE=1
QUEUE_NUM_POSTROUTE=10

# sudo ip6tables -t mangle -I PREROUTING -j NFQUEUE --queue-num $QUEUE_NUM_PREROUTE
# sudo ip6tables -t mangle -I POSTROUTING -j NFQUEUE --queue-num $QUEUE_NUM_POSTROUTE

sudo ip6tables -t mangle -m ipv6header --soft --header ipv6-route -I PREROUTING -j NFQUEUE --queue-num $QUEUE_NUM_PREROUTE
sudo ip6tables -t mangle -m ipv6header --soft --header ipv6-route -I POSTROUTING -j NFQUEUE --queue-num $QUEUE_NUM_POSTROUTE

while getopts "s" ARGS;
do
    case $ARGS in
    s )
        sudo python3 collector_agent.py -v --ip $IP --port $PORT --nfqueue_num_pre $QUEUE_NUM_PREROUTE --nfqueue_num_post $QUEUE_NUM_POSTROUTE --log_file $1 -s --node_id $2
        ;;
    * )
        sudo python3 collector_agent.py -v --ip $IP --port $PORT --nfqueue_num_pre $QUEUE_NUM_PREROUTE --nfqueue_num_post $QUEUE_NUM_POSTROUTE --log_file $1
        ;;
    esac
done