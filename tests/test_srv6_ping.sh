#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts.sh -d

sudo ./setup.sh

cd ..
sudo ./install.sh
cd -

set -e

sudo ./netns_network_examples/simple/2hosts.sh -c
# start agent
sudo ip netns exec ns2 srv6_nfagent -s --node_id 1 &
# run test
sudo ip netns exec ns1 python3 -m unittest discover ./
sudo ./netns_network_examples/simple/2hosts.sh -d
sudo rm -rf ./srv6_ping/