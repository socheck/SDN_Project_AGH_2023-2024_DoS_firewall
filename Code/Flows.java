package pl.edu.agh.kt;


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwSrc.Builder;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.VlanVid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.statistics.StatisticsCollector;



public class Flows {
	private static final Logger logger = LoggerFactory.getLogger(Flows.class);

	public static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
	public static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	public static short FLOWMOD_DEFAULT_PRIORITY = 100;

	protected static boolean FLOWMOD_DEFAULT_MATCH_VLAN = true;
	protected static boolean FLOWMOD_DEFAULT_MATCH_MAC = true;
	protected static boolean FLOWMOD_DEFAULT_MATCH_IP_ADDR = true;
	protected static boolean FLOWMOD_DEFAULT_MATCH_TRANSPORT = true;

	public Flows() {
		logger.info("Flows() begin/end");
	}

	public static void simpleAdd(IOFSwitch sw, OFPacketIn pin, FloodlightContext cntx, OFPort outPort) {
		PacketExtractor extractor = new PacketExtractor(cntx);
		String sourceMac = extractor.getSourceMac().toString();

//		Map<String, Integer> blackList = StatisticsCollector.blackList;

		// FlowModBuilder
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();

		// match
		Match m = createMatchFromPacket(sw, pin.getInPort(), cntx);

		// actions
		OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();

		List<OFAction> actions = new ArrayList<OFAction>();

		aob.setPort(outPort);
		aob.setMaxLen(Integer.MAX_VALUE);
		actions.add(aob.build());
		fmb.setMatch(m).setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT).setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
				.setBufferId(pin.getBufferId()).setOutPort(outPort).setPriority(FLOWMOD_DEFAULT_PRIORITY);

		fmb.setActions(actions);

		// write flow to switch
		try {
			sw.write(fmb.build());
//				logger.info("Flow from port {} forwarded to port {}; match: {}", new Object[] { pin.getInPort().getPortNumber(), outPort.getPortNumber(), m.toString() });
		} catch (Exception e) {
			logger.error("error {}", e);
		}
	}

	public static void deleteFlow(IOFSwitch sw, MacAddress srcMac) {

		// Create a flow delete message
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_SRC, srcMac);
		Match match = mb.build();

		OFFlowDelete.Builder flowDeleteBuilder = sw.getOFFactory().buildFlowDelete();
		flowDeleteBuilder.setMatch(match);
		flowDeleteBuilder.setOutPort(OFPort.ANY);  // Set to any port for wildcard match

		// Send the flow delete message to the switch
		try {
			sw.write(flowDeleteBuilder.build());
			logger.info("Flow matching {} deleted.", match.toString());
		} catch (Exception e) {
			logger.error("Error deleting flow: {}", e.getMessage());
		}
	}

	public static Match createMatchFromSourceMac(IOFSwitch sw, MacAddress srcMac) {
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_SRC, srcMac);

		return mb.build();
	}

	public static Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {

		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		Match.Builder mb = sw.getOFFactory().buildMatch();

		mb.setExact(MatchField.IN_PORT, inPort);

		if (FLOWMOD_DEFAULT_MATCH_MAC) {
			mb.setExact(MatchField.ETH_SRC, srcMac).setExact(MatchField.ETH_DST, dstMac);
		}

		if (FLOWMOD_DEFAULT_MATCH_VLAN) {
			if (!vlan.equals(VlanVid.ZERO)) {
				mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
			}
		}

		// TODO Detect switch type and match to create hardware-implemented flow
		if (eth.getEtherType() == EthType.IPv4) { /*
		 * shallow check for equality is okay for EthType

		 */
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcIp = ip.getSourceAddress();
			IPv4Address dstIp = ip.getDestinationAddress();

			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv4).setExact(MatchField.IPV4_SRC, srcIp)
						.setExact(MatchField.IPV4_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*

				 * Take care of the ethertype if not included earlier, since it's a prerequisite

				 * for transport ports.

				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				}

				if (ip.getProtocol().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP).setExact(MatchField.TCP_SRC, tcp.getSourcePort())
							.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} 
				else if (ip.getProtocol().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP).setExact(MatchField.UDP_SRC, udp.getSourcePort())
							.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		} 
		else if (eth.getEtherType() == EthType.ARP) { /*

		 * shallow check for equality is okay for EthType

		 */
			mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
		}

		return mb.build();
	}
	public static void handlePacket(
            IOFSwitch sw, 
            OFMessage msg,
            FloodlightContext cntx,
            IPv4Address specificSrcIp, 
            IPv4Address specificDstIp, 
            DatapathId specificID,
            OFPort specificInPort, 
            OFPort specificOutPort) {
            
        OFPacketIn pin = (OFPacketIn) msg;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (eth.getPayload() instanceof IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            IPv4Address srcIp = ipv4.getSourceAddress();
            IPv4Address dstIp = ipv4.getDestinationAddress();
            DatapathId switchId = sw.getId();

            
           if (pin.getInPort().equals(specificInPort) && srcIp.equals(specificSrcIp) && dstIp.equals(specificDstIp)  &&  switchId.equals(specificID) ) {

			       	 OFPort outPort=specificOutPort;
					 
					 OFPacketIn pi = pin;
					 
					 OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
							 : pi.getMatch().get(MatchField.IN_PORT));
					 
					 OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
					 List<OFAction> actions1= new ArrayList<OFAction>();
					 actions1.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build());
					 pob.setActions(actions1);
			 
					 if (sw.getBuffers() == 0) {
						 pi = pi.createBuilder().setBufferId(OFBufferId.NO_BUFFER).build();
						 pob.setBufferId(OFBufferId.NO_BUFFER);
						 logger.info("The switch doesn't support buffering");
						 } else {
						 pob.setBufferId(pi.getBufferId());
						 }
					 if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
						 byte[] packetData = pi.getData();
						 pob.setData(packetData);
						 }
		 
		 
					 sw.write(pob.build());

       			Flows.simpleAdd(sw, pin, cntx, specificOutPort);

            }
        }
        
        
    }
	
	
	public static void allTrace(
            IOFSwitch sw, 
            OFMessage msg,
            FloodlightContext cntx) {
    	
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(2), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(2), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(1), OFPort.of(5));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(2), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(1), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(2), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(2), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(2), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(1), OFPort.of(5));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(3), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(3), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(3), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(2), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(3), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(1), OFPort.of(5));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(2), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(4), OFPort.of(5));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(4), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(4), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(1), OFPort.of(2));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(1));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(2), OFPort.of(4));

    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(4));
    	handlePacket(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(3), OFPort.of(4));
    	
}
    
    
	public static void handlePacketARP(
            IOFSwitch sw, 
            OFMessage msg,
            FloodlightContext cntx,
            IPv4Address specificSrcIp, 
            IPv4Address specificDstIp, 
            DatapathId specificID,
            OFPort specificInPort, 
            OFPort specificOutPort) {
    	
    	OFPacketIn pin = (OFPacketIn) msg;
        DatapathId switchId = sw.getId();

  		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
    	ARP arp = (ARP) eth.getPayload();
		
		IPv4Address dstIp = arp.getTargetProtocolAddress();
		IPv4Address srcIp = arp.getSenderProtocolAddress();
		
		 if (pin.getInPort().equals(specificInPort)  ) {
			 if(dstIp.equals(specificDstIp)){
				 if( switchId.equals(specificID)){
					 
					 OFPort outPort=specificOutPort;
						
					 
					 OFPacketIn pi = pin;
					 
					 OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
							 : pi.getMatch().get(MatchField.IN_PORT));
					 
					 OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
					 List<OFAction> actions1= new ArrayList<OFAction>();
					 actions1.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build());
					 pob.setActions(actions1);
			 
					 if (sw.getBuffers() == 0) {
						 pi = pi.createBuilder().setBufferId(OFBufferId.NO_BUFFER).build();
						 pob.setBufferId(OFBufferId.NO_BUFFER);
						 } else {
						 pob.setBufferId(pi.getBufferId());
						 }
					 if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
						 byte[] packetData = pi.getData();
						 pob.setData(packetData);
						 }
					 
					 sw.write(pob.build());

					 
					 
					List<OFAction> actions = new ArrayList<OFAction>();

						Builder actionChangeIpAddSrc = sw.getOFFactory().actions().buildSetNwSrc();
						actionChangeIpAddSrc.setNwAddr(srcIp);
						actions.add(actionChangeIpAddSrc.build());
						

					 OFActionOutput.Builder actionOutPort = sw.getOFFactory().actions().buildOutput();
						actionOutPort.setPort(specificOutPort);
						actionOutPort.setMaxLen(Integer.MAX_VALUE);
						actions.add(actionOutPort.build());

						OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
						Match m = createMatchFromPacket(sw, pin.getInPort(), cntx);
	
						fmb.setMatch(m).setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT).setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
								.setBufferId(pin.getBufferId()).setOutPort(specificOutPort).setPriority(FLOWMOD_DEFAULT_PRIORITY);
						fmb.setActions(actions);

						try {
							sw.write(fmb.build());
							logger.info("Flow from port {} forwarded to port {}; match: {}",
									new Object[] { pin.getInPort().getPortNumber(), specificOutPort.getPortNumber(), m.toString() });
						} catch (Exception e) {
							logger.error("error {}", e);
						}
					 
					
					 
				 }
				 
			 }
	       		

	        }
   	
        
        
    }


	public static void allTraceARP(
            IOFSwitch sw, 
            OFMessage msg,
            FloodlightContext cntx) {
    	
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(2), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(2), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(1), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(1), OFPort.of(5));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.1"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(2), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(1), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(2), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(2), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(2), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(2), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(1), OFPort.of(5));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(3), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(3), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(3), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(2), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(3), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(1), OFPort.of(5));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(3), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(2), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(4), OFPort.of(5));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.4"), IPv4Address.of("10.0.0.5"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(3), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(4), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.1"), DatapathId.of("00:00:00:00:00:00:00:01"), OFPort.of(2), OFPort.of(1));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(4), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:03"), OFPort.of(1), OFPort.of(2));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.2"), DatapathId.of("00:00:00:00:00:00:00:06"), OFPort.of(1), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(1));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:02"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:04"), OFPort.of(1), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.3"), DatapathId.of("00:00:00:00:00:00:00:07"), OFPort.of(2), OFPort.of(4));

    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:09"), OFPort.of(4), OFPort.of(3));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:05"), OFPort.of(5), OFPort.of(4));
    	handlePacketARP(sw, msg, cntx, IPv4Address.of("10.0.0.5"), IPv4Address.of("10.0.0.4"), DatapathId.of("00:00:00:00:00:00:00:08"), OFPort.of(3), OFPort.of(4));
    	}

	
}
