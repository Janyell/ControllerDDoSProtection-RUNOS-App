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
        hosts = []
        # h1 - valid user, h2 - invalid malicious user, h3 - invalid DDoS user
        n = 15
        for i in xrange( n ):
            hosts.append( self.addHost( 'h' + str( i + 1 ) ) )

        s1 = self.addSwitch( 's1', protocols='OpenFlow13' )
        
        # Add links between switches and hosts
        for i in xrange( len( hosts ) ):
            self.addLink( hosts[i], s1 )

if __name__ == '__main__':

    testTopo = TestTopo()
    remoteCtrl = RemoteController( 'ctrl', ip='127.0.0.1', port=6653 )
    net = Mininet( topo=testTopo, controller=remoteCtrl, switch=OVSKernelSwitch, autoSetMacs=True )

    # Connect real interfaces to switch
    Intf( 'brApache', node=net.switches[0] ) # Apache server
    # Intf( 'enp0s3 ', node=net.switches[0] ) # Internet

    net.start()
    net.interact()
