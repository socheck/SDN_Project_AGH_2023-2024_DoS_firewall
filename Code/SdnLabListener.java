package pl.edu.agh.kt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import java.util.HashMap;

import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFFlowStatsRequest;

import org.projectfloodlight.openflow.protocol.OFMessage;

import org.projectfloodlight.openflow.protocol.OFPacketIn;

import org.projectfloodlight.openflow.protocol.OFType;

import org.projectfloodlight.openflow.protocol.match.MatchField;

import org.projectfloodlight.openflow.protocol.match.Match;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TableId;

import org.projectfloodlight.openflow.types.IpProtocol;

import org.projectfloodlight.openflow.types.OFPort;

import org.projectfloodlight.openflow.types.U64;

import net.floodlightcontroller.core.FloodlightContext;

import net.floodlightcontroller.core.IOFMessageListener;

import net.floodlightcontroller.core.IOFSwitch;

import net.floodlightcontroller.core.module.FloodlightModuleContext;

import net.floodlightcontroller.core.module.FloodlightModuleException;

import net.floodlightcontroller.core.module.IFloodlightModule;

import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;

import net.floodlightcontroller.packet.Ethernet;

import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.packet.TCP;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;

import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;

import pl.edu.agh.kt.StatisticsCollector.PortStatisticsPoller;

public class SdnLabListener implements IFloodlightModule, IOFMessageListener {

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
	public net.floodlightcontroller.core.IListener.Command receive(

	IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		HashMap<String, Integer> checkMap = new HashMap<>();
		
		int counter = 2;

		logger.info("************* NEW PACKET IN *************");

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		String srcMac = eth.getSourceMACAddress().toString();
		
		// S - 02

		// R - 04

		// A - 16

		if (eth.getPayload() instanceof IPv4) {

			IPv4 ipv4 = (IPv4) eth.getPayload();

			if (ipv4.getProtocol().equals(IpProtocol.TCP)) {

				TCP tcp = (TCP) ipv4.getPayload();

				// logger.info(tcp.getFlags());

				// logger.info("Frame: TCP get flags {}", tcp.getFlags());

				logger.info("Frame: TCP get flags {}", tcp.getFlags());

				if (tcp.getFlags() == 2) {

					logger.info("Otrzymano pakiet TCP z flaga SYN");
					logger.info("srcMac {}", srcMac );
					logger.info("counter {}", counter);
					logger.info("Hash mapa {}", checkMap );
					
					if (checkMap.containsKey(srcMac)) {
						logger.info("Juz kiedys taki mac byl: {}", srcMac);
						checkMap.put(srcMac, counter);
						counter += 1;
						logger.info("Counter {}", counter);
					} else {
						logger.info("Pierwszy raz widze mac: {}", srcMac);
						checkMap.put(srcMac, counter);
					}
					
					return Command.STOP;

				}
				

			}

		}

		PacketExtractor extractor = new PacketExtractor(cntx, msg);

		// TODO LAB 6

		OFPacketIn pin = (OFPacketIn) msg;

		OFPort outPort;

		outPort = OFPort.of(extractor.getDstPort());

		Flows.simpleAdd(sw, pin, cntx, outPort);

		// StatisticsCollector.getInstance(sw, cntx);

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
	public void init(FloodlightModuleContext context)

	throws FloodlightModuleException {

		floodlightProvider = context

		.getServiceImpl(IFloodlightProviderService.class);

		logger = LoggerFactory.getLogger(SdnLabListener.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context)

	throws FloodlightModuleException {

		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

		logger.info("******************* START **************************");

	}

}
