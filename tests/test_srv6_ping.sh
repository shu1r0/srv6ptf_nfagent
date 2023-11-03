#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts_1router.sh -d

sudo ./setup.sh

cd ..
sudo ./install.sh
cd -

set -e


# Agent Standalone
# -- Start network
sudo ./netns_network_examples/simple/2hosts_1router.sh -c

# start agent
sudo ip netns exec r1 srv6_nfagent -s --node_id 1 &

# run test
sudo ip netns exec h1 python3 -m unittest test_brackbox.py

sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# -- Stop network


# Agent
# -- Start network
sudo ./netns_network_examples/simple/2hosts_1router.sh -

# start agent
sudo ip netns exec r1 srv6_nfagent &

# run test
sudo ip netns exec h1 python3 -m unittest test_brackbox_client.py

sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# -- Stop network


sudo rm -rf ./srv6_ping/
