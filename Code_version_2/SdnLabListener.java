package pl.edu.agh.kt;

import java.util.Collection;
import java.util.Map;

import javax.crypto.spec.RC2ParameterSpec;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class SdnLabListener implements IFloodlightModule, IOFMessageListener {

	HashMap<MapKey, TcpSynFlow> known_syn_flows_map = new HashMap<>();
	float RATIO_THRESHOLD = 5; // SYN packets per second

	class TcpSynFlow {
		private int counter;
		private double timestamp;
		private double ratio;

		public void setCounter(int counter) {
			this.counter = counter;
		}

		public void setTimestamp(long timestamp) {
			this.timestamp = timestamp;
		}

		public void setRatio(float ratio) {
			this.ratio = ratio;
		}

		public int getCounter() {
			return counter;
		}

		public double getTimestamp() {
			return timestamp;
		}

		public double getRatio() {
			return ratio;
		}

		public TcpSynFlow(int counter, double current_time, double new_ratio) {
			this.counter = counter;
			this.timestamp = current_time;
			this.ratio = new_ratio;
		}
		
	}

	class MapKey {
		private String srcMac;
		private String dpid;

		public MapKey(String srcMac, String dpid){
			this.srcMac = srcMac;
			this.dpid = dpid;
		}

		public void setSrcMac(String srcMac) {
			this.srcMac = srcMac;
		}

		public void setDpid(String dpid) {
			this.dpid = dpid;
		}

		public String getSrcMac() {
			return srcMac;
		}

		public String getDpid() {
			return dpid;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			MapKey mapKey = (MapKey) o;
			return srcMac.equals(mapKey.srcMac) && dpid.equals(mapKey.dpid);
			}

		@Override
		public int hashCode() {
			return Objects.hash(srcMac, dpid);
		}
	}


	// Convert String to MAC Address

	public MacAddress strToMac(String macString) {
		String[] parts = macString.split(":");
		byte[] macBytes = new byte[6];

		for (int i = 0; i < 6; i++) {
			macBytes[i] = (byte) Integer.parseInt(parts[i], 16);
		}

		return MacAddress.of(macBytes);
	}






	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;

	@Override
	public String getName() {
		return SdnLabListener.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {

		//logger.info("************* NEW PACKET IN *************");
		PacketExtractor extractor = new PacketExtractor();
		extractor.packetExtract(cntx);
		OFPacketIn pin = (OFPacketIn) msg;
		// OFPort outPort = OFPort.of(0);
		// if (pin.getInPort() == OFPort.of(1)) {
		// 	outPort = OFPort.of(2);
		// } else
		// 	outPort = OFPort.of(1);
		// Flows.simpleAdd(sw, pin, cntx, outPort);


		
			

		/* Rest handling for our topology */
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);


		// Extracting IPv4
		if (eth.getPayload() instanceof IPv4) {
			IPv4 ipv4 = (IPv4) eth.getPayload();

			// Checking if TCP 
			if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ipv4.getPayload();
				// logger.info("Frame: TCP get flags {}", tcp.getFlags());

				//Check if TCP SYN
				if (tcp.getFlags() == 2) {
					
					logger.warn("================ Otrzymano pakiet TCP z flaga SYN ===============");
					
					double current_time = (long) System.currentTimeMillis();
					
					// Get MACAddress of an possible attacker
					String srcMac = eth.getSourceMACAddress().toString();
					String dpid = sw.getId().toString();
					logger.warn("================ Switch ID, ktory otrzymal TCP SYN: {} ===============", dpid);
					MapKey buff_mapKey = new MapKey(srcMac, dpid);
					//logger.info("================ DPID {}  ===============", sw.getId());

					// Do we have this 'gagatek' in our HashMap?
					if (known_syn_flows_map.containsKey(buff_mapKey)){

						// logger.info("================ DPID2 {}  ===============", sw.getId());
						
						
						TcpSynFlow old_tcp_syn_flow = known_syn_flows_map.get(buff_mapKey); 
						logger.info("================ Current ratio: {} ===============", old_tcp_syn_flow.getRatio());
						
						int new_counter = old_tcp_syn_flow.getCounter() + 1;
						double old_time_stamp = old_tcp_syn_flow.getTimestamp();
						// logger.info("================ old time: {} ===============", old_time_stamp);
						
						double new_ratio = (new_counter / (Math.max(current_time - old_time_stamp, 1)));
						
						TcpSynFlow updated_tcp_syn_flow = new TcpSynFlow(new_counter, current_time, new_ratio);
						known_syn_flows_map.put(buff_mapKey, updated_tcp_syn_flow);

						// Checking Threshold status
						// logger.info("================ new ratio {}  ===============", new_ratio);

						if (new_ratio > RATIO_THRESHOLD){
							// Sending Ban to the Switch
							logger.warn("================ BANUJ  ===============");
							logger.info("================ DPID {}  ===============", sw.getId());
							logger.info("================ RATIO {}  ===============", new_ratio);
							//logger.info("================ hashmap {}  ===============", sw.getId());
							Flows.banFlow(sw, pin, cntx, null,eth.getSourceMACAddress());
							return Command.STOP;
						}
						if (current_time - old_time_stamp > 20000){
							TcpSynFlow updated_tcp_syn_flow1 = new TcpSynFlow(1, current_time, new_ratio);
							known_syn_flows_map.put(buff_mapKey, updated_tcp_syn_flow1);
						}
						Flows.allTraceSendPacketOut(sw, pin, cntx);
						return Command.STOP;

					}
					else {
						MapKey mapKey = new MapKey(srcMac, dpid);
						TcpSynFlow tcpSynFlow = new TcpSynFlow(1, current_time , 0);
						known_syn_flows_map.put(mapKey, tcpSynFlow);
						Flows.allTraceSendPacketOut(sw, pin, cntx);
						return Command.STOP;
					}



			}

			}
		}

		if (eth.getEtherType() == EthType.ARP){
            Flows.allTraceARP(sw, pin, cntx);
        }
         
		Flows.allTrace(sw, pin, cntx);

		return Command.STOP;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(SdnLabListener.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		logger.info("******************* START **************************");

	}

}

