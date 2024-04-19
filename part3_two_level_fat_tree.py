from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
from mininet.link import Link, Intf, TCLink
import os 
from time import sleep
import sys

class TwoLevelFatTree(Topo):

    def __init__(self, N):
        
        # N = 2
        try:
            N = int(N)
            if N % 2 != 0:
                raise ValueError("N = %d is not an even number" % N)
        except ValueError as ve:
            print(ve)
            exit(1)

        Topo.__init__(self)

        switch_size = int(N) # K
        level = 2 # L
        host_num = 2 * (switch_size / 2) ** level
        edge_switch_num = switch_size
        core_switch_num = (switch_size / 2) ** (level - 1)

        host_num_per_switch = switch_size / 2
       
        host_list = []
        core_switch_list = []
        edge_switch_list = []

        # Adding host
        for c in range(core_switch_num):
            core_switch = self.addSwitch('sc%d' % (c)) # switch_core
            core_switch_list.append(core_switch)
            
        # Adding edge switches
        for e in range(edge_switch_num):
            edge_switch = self.addSwitch('se%d' % (e)) # switch_edge
            edge_switch_list.append(edge_switch)
            for cs in core_switch_list:
                self.addLink(cs, edge_switch)

            # Adding core switches
            for h in range(host_num_per_switch):
                host = self.addHost("h%d_%d" % (e, h)) # host_(switch_id)_(host_id)
                host_list.append(host)
                self.addLink(host, edge_switch)

        print(edge_switch_list)

# This is for "mn --custom"        
topos = { 'mytopo': ( lambda: TwoLevelFatTree(input("Enter the number of port of switch: ")) )}




# This is for "python *.py"
if __name__ == '__main__':
    setLogLevel( 'info' )
    
    N = input("Enter the number of port of switch: ")
    topo = TwoLevelFatTree(N)
    net = Mininet(topo=topo, link=TCLink)       # The TCLink is a special setting for setting the bandwidth in the future.
    
    # 1. Start mininet
    net.start()
    
    
    # Wait for links setup (sometimes, it takes some time to setup, so wait for a while before mininet starts)
    print("\nWaiting for links to setup . . . .")
    sys.stdout.flush()
    for time_idx in range(3):
        print(".")
        sys.stdout.flush()
        sleep(1)
    
        
    # 2. Start the CLI commands
    info( '\n*** Running CLI\n' )
    CLI( net )
    
    
    # 3. Stop mininet properly
    net.stop()


    ### If you did not close the mininet, please run "mn -c" to clean up and re-run the mininet         
