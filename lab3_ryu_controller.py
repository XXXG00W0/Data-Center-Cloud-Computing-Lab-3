from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp, udp, icmp, ipv4, ipv6, arp
from ryu.ofproto import ether
# from ryu.lib.packet import udp



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.my_arp_table = {'10.0.0.1': '10:00:00:00:00:01',
                             '10.0.0.2': '10:00:00:00:00:02',
                             '10.0.0.3': '10:00:00:00:00:03',
                             '10.0.0.4': '10:00:00:00:00:04',}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        dst_mac = eth_pkt.dst # dst mac
        src_mac = eth_pkt.src # src mac

        self.logger.info("packet in switch %s src mac %s dst mac %s from port %s", dpid, src_mac, dst_mac, in_port)
        # self.logger.info("eth_pkt.ethertype %s ==? IP %s", eth_pkt.ethertype, ether_types.ETH_TYPE_IP)
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.src
        else:
            src_ip = ""
            dst_ip = ""

        # Determine action based on packet type and specific rules
        actions = []
        if pkt.get_protocol(arp.arp):
            arp_pkt = pkt.get_protocol(arp.arp)
            self.logger.info("ARP host %s (%s) asks %s (%s)", 
                             arp_pkt.src_ip, arp_pkt.src_mac,
                             arp_pkt.dst_ip, arp_pkt.dst_mac)
            self.handle_arp_requst(datapath, in_port, eth_pkt, arp_pkt)
            return
        elif pkt.get_protocol(tcp.tcp):
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            # Check for TCP SYN packets to dpid 2 or 4 from specific source IPs
            if (dpid == 2 or dpid == 4) and (src_ip == '10.0.0.2' or src_ip == '10.0.0.4') and tcp_pkt.bits & tcp.TCP_SYN:
                self.send_tcp_rst(datapath, in_port, src_ip, ip_pkt.dst, tcp_pkt.src_port, tcp_pkt.dst_port, tcp_pkt.seq)
                return  # Drop the packet and send TCP RST
            else:
                actions = [parser.OFPActionOutput(2)]  # Forward TCP and ICMP packets to port 2
        elif pkt.get_protocol(udp.udp) and not (src_ip == '10.0.0.2' or src_ip == '10.0.0.4'):
            actions = [parser.OFPActionOutput(3)]  # Forward UDP packets to port 3 unless from specific source IPs
        elif pkt.get_protocol(icmp.icmp):
            actions = [parser.OFPActionOutput(2)]  # Forward ICMP packets to port 2
        else:
            self.logger.info("Packet not follow any rules")
            return
        # Install flow to avoid packet_in next time if actions are defined
        if actions:
            if src_ip != "":
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_pkt.ethertype, ipv4_src=src_ip, ipv4_dst=dst_ip)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_pkt.ethertype)
            self.add_flow(datapath, 1, match, actions)
        
        # Forward the packet according to the actions
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def send_tcp_rst(datapath, in_port, src_eth, dst_eth, src_ip, dst_ip, src_port, dst_port, tcp_ack):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Layer 2 Ethernet
        eth_pkt =ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP, dst=src_eth, src=dst_eth)

        # Layer 3 IP
        ip_pkt = ipv4.ipv4(dst=src_ip, src=dst_ip, proto=6)

        # Layer 4 TCP
        tcp_pkt = tcp.tcp(dst_port=src_port, src_port=dst_port, 
                            ack=tcp_ack+1, bits=(tcp.TCP_RST|tcp.TCP_ACK))
        
        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ip_pkt)
        pkt.add_protocol(tcp_pkt)
        pkt.serialize()

        actions = [parser.OFPActionOutput(port=in_port)]
        msg = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(msg)

    def handle_arp_requst(self, datapath, in_port, eth_pkt, arp_pkt):
        self.send_arp_reply(datapath, eth_pkt, arp_pkt, in_port)

    def send_arp_reply(self, datapath, eth_pkt, arp_pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        dst_mac = self.my_arp_table[arp_pkt.src_ip]
        src_mac = self.my_arp_table[arp_pkt.dst_ip]
        src_ip = arp_pkt.dst_ip
        dst_ip = arp_pkt.src_ip
        out_port = in_port

        arp_reply_pkt = packet.Packet()
        arp_reply_pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                                     dst=dst_mac, src=src_mac))
        arp_reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, 
                                           dst_mac=dst_mac, src_ip=src_ip, dst_ip=dst_ip))
        arp_reply_pkt.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                  data=arp_reply_pkt.data)
        arp_pkt = arp_reply_pkt.get_protocol(arp.arp)
        self.logger.info("ARP host %s (%s) replys %s (%s)", 
                            arp_pkt.src_ip, arp_pkt.src_mac,
                            arp_pkt.dst_ip, arp_pkt.dst_mac)
        datapath.send_msg(out)