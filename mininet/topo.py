#! /usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.link import Intf

class TestTopo( Topo ):

    def __init__( self ):

        # Initialize topology
        Topo.__init__( self )

        # Add hosts
        h1 = self.addHost( 'h1' ) # Valid user
        h2 = self.addHost( 'h2' ) # Invalid malicious user
        h3 = self.addHost( 'h3' ) # Invalid DDoS user
        
        s1 = self.addSwitch( 's1', protocols='OpenFlow13')

        # Add links between switches and hosts
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )

if __name__ == '__main__':

    testTopo = TestTopo()
    remoteCtrl = RemoteController('ctrl', ip='127.0.0.1', port=6653)
    net = Mininet(topo=testTopo, controller=remoteCtrl, switch=OVSKernelSwitch, autoSetMacs=True)

    # Connect real interfaces to switch
    Intf('brApache', node=net.switches[0]) # Apache server
    # Intf('enp0s3 ', node=net.switches[0]) # Internet

    net.start()
    net.interact()
