from mininet.topo import Topo
from mininet.net import Containernet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from normal_traffic import *

setLogLevel('info')

net = Containernet(controller=RemoteController, switch=OVSKernelSwitch) #remote controller

info('*** Adding controller\n')

c0 = net.addController('c0', controller=RemoteController, ip= '172.17.0.6')


info('*** Adding docker containers\n')

PC1 = net.addHost( 'PC1', mac='00:00:00:00:00:11', ip='10.0.0.1/8' )
PC2 = net.addHost( 'PC2', mac='00:00:00:00:00:22', ip='10.0.0.2/8' )
PC3 = net.addHost( 'PC3', mac='00:00:00:00:00:33', ip='10.0.0.3/8' )
PC4 = net.addHost( 'PC4', mac='00:00:00:00:00:44', ip='10.0.0.4/8' )
PC5 = net.addHost( 'PC5', mac='00:00:00:00:00:55', ip='10.0.0.5/8' )

info('*** Adding switches\n')

s1 = net.addSwitch( 's1', mac='00:00:00:00:11:00')
s2 = net.addSwitch( 's2', mac='00:00:00:00:22:00')
s3 = net.addSwitch( 's3', mac='00:00:00:00:33:00')
s4 = net.addSwitch( 's4', mac='00:00:00:00:44:00')
s5 = net.addSwitch( 's5', mac='00:00:00:00:55:00')
s6 = net.addSwitch( 's6', mac='00:00:00:00:66:00')
s7 = net.addSwitch( 's7', mac='00:00:00:00:77:00')
s8 = net.addSwitch( 's8', mac='00:00:00:00:88:00')
s9 = net.addSwitch( 's9', mac='00:00:00:00:99:00')

info('*** Creating links\n')
# Add links
net.addLink( PC1, s1 )
net.addLink( s1, s2 )
net.addLink( s2, s3 )
net.addLink( s2, s4 )
net.addLink( s2, s5 )

net.addLink( s3, s6 )
net.addLink( s3, s7 )
net.addLink( s3, s8 )
net.addLink( s3, s9 )

net.addLink( s4, s6 )
net.addLink( s4, s7 )
net.addLink( s4, s8 )
net.addLink( s4, s9 )

net.addLink( s5, s6 )
net.addLink( s5, s7 )
net.addLink( s5, s8 )
net.addLink( s5, s9 )

net.addLink( s6, PC2 )
net.addLink( s7, PC3 )
net.addLink( s8, PC4 )
net.addLink( s9, PC5 )

info('*** Starting network\n')

net.build()
c0.start()

s1.start([ c0 ])
s2.start([ c0 ])
s3.start([ c0 ])
s4.start([ c0 ])
s5.start([ c0 ])
s6.start([ c0 ])
s7.start([ c0 ])
s8.start([ c0 ])
s9.start([ c0 ])


info('*** Testing connectivity\n')
net.ping([PC1, PC2,])
net.ping([PC5, PC3,])
info('*** Running CLI\n')
PC2.cmd(create_query(source_ip_addr="10.0.0.2", destination_ip_addr="10.0.0.3", wait_time=1))
PC2.cmd(create_query(source_ip_addr="10.0.0.2", destination_ip_addr="10.0.0.4", wait_time=1))
PC2.cmd(create_query(source_ip_addr="10.0.0.2", destination_ip_addr="10.0.0.5", wait_time=1))
PC5.cmd(create_query(source_ip_addr="10.0.0.5", destination_ip_addr="10.0.0.3", wait_time=1))
CLI(net)
info('*** Stopping network')


net.stop()



