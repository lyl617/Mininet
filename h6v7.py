#!/usr/bin/python

"""
topology with 6 switches and 7 hosts
"""

from mininet.cli import CLI
from mininet.topo import Topo 
from mininet.net import Mininet 
from mininet.link import TCLink
from mininet.log import setLogLevel

class HRTopo(Topo):
    def __init__(self):
        "create topology"

        Topo.__init__(self)

        # hosts = []
        # #add hosts
        # num_hosts = 6
        # for i in range(num_hosts):
        #     host = self.addHost('h{}'.format(i+1))
        #     hosts.append(host)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        # switches = []
        # num_switches = 7
        # for i in range(num_switches):
        #     sw = self.addSwitch('s{}'.format(i+1))
        #     switches.append(sw)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        #add links between hosts and switches
        self.addLink()
