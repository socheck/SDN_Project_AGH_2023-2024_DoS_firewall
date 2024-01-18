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

	HashMap<String, MacAddressInfo> checkMap = new HashMap<>(); //przetrzymuje adres mac: counter, czas
	HashMap<String, MacAddressBlacklist> blacklistMap = new HashMap<>();

	int counter = 0; //zmienna przechowujaca licznik
	long actual_time = 0; //aktualny czas systemowy
	int threshold = 100; //minimalny odstep miedzy pakietami SYN[ms]
	long hard_time = 10000; //timeout adresu MAC po ataku SYN[ms]

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

	//klasa do utworzenia struktury Hashmap z 2 wartosciami -> mac_address: counter, time
	class MacAddressInfo {
		private int counter;
		private long timestamp;

		public MacAddressInfo(int counter, long timestamp) {
			this.counter = counter;
			this.timestamp = timestamp;
		}

		public int getCounter() {
			return counter;
		}

		public void setCounter(int counter) {
			this.counter = counter;
		}

		public long getTimestamp() {
			return timestamp;
		}

		public void setTimestamp(long timestamp) {
			this.timestamp = timestamp;
		}
		
	}
	
	class MacAddressBlacklist {
		
		private boolean blacklisted;
		private long blacklist_timer;
		
		public MacAddressBlacklist(boolean blacklisted, long blacklist_timer) {
			this.blacklisted = blacklisted;
			this.blacklist_timer = actual_time;
		}
		
		public boolean getBlacklisted() {
			return blacklisted;
		}
	
		public void setBlacklisted(boolean blacklisted) {
			this.blacklisted = blacklisted;
		}
		
		public long getBlacklistTimer() {
			return blacklist_timer;
		}
	
		public void setBlacklistTimer(int blacklist_timer) {
			this.blacklist_timer = blacklist_timer;
		}
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
//		logger.info("************* NEW PACKET IN *************");

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		String srcMac = eth.getSourceMACAddress().toString();

		// S - 02
		// R - 04
		// A - 16

		if (eth.getPayload() instanceof IPv4) {
			IPv4 ipv4 = (IPv4) eth.getPayload();

			if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ipv4.getPayload();
				logger.info("Frame: TCP get flags {}", tcp.getFlags());

				if (tcp.getFlags() == 2) {
					logger.info("Otrzymano pakiet TCP z flaga SYN");
					actual_time = System.currentTimeMillis();

					if (checkMap.containsKey(srcMac)) {
						
						if(!blacklistMap.containsKey(srcMac)) { // adres MAC nie jest zblacklistowany
							
							counter = checkMap.get(srcMac).getCounter(); //pobranie aktualnej wartosci licznika dla danego adresu MAC
							counter += 1; //zaktualizowanie licznika
							
							if (counter >= 5){ // krotsze czasy aby zaobserowac blacklisting
								
								long time_diff = actual_time - checkMap.get(srcMac).getTimestamp();
								logger.info("Time diff: {}", time_diff);
								
								if (time_diff <= 1500){  // krotsze czasy aby zaobserowac blacklisting
									
									blacklistMap.put(srcMac, new MacAddressBlacklist(true, actual_time)); // ustawienie wartosci true i czas kiedy zostal zblacklistowany
									
									//TODO - usuniecie flowu z przelacznika, do poprawy to tutaj
									//Flows.deleteFlow(sw, stringToMacAddress(srcMac));
									
									logger.info("Adres MAC: {} zostal dodany do blacklisty", srcMac);
									checkMap.put(srcMac, new MacAddressInfo(0, actual_time)); //wyzerowanie wystepowan po dodaniu do blacklisty
								}
							}
							
							else {
								checkMap.put(srcMac, new MacAddressInfo(counter, actual_time));
							}
							
							//wypisanie danych struktury
//							logger.info("Adres MAC(ponowne wystapienie): {}", srcMac);
//							logger.info("Counter: {}", checkMap.get(srcMac).getCounter());
//							logger.info("Timestamp: {}", checkMap.get(srcMac).getTimestamp());
							
						}
						
						else { //maszyna JEST zblacklistowana
							
							// TODO: obsluga zmniejszania czasu z blacklisty i sprawdzanie czy juz minelo na tyle
							
							for (String macAddress : blacklistMap.keySet()) { // sprawdzamy wszytskie wpisy w tablicy blacklistujacej nie tylko dla maca tego
								long time_diff = System.currentTimeMillis() - blacklistMap.get(srcMac).getBlacklistTimer();
								MacAddressBlacklist info = blacklistMap.get(macAddress);
								
								if (time_diff > 5000) {
									logger.info("Odblacklistowujemy :D");
									blacklistMap.remove(srcMac);
								} else {
									logger.info("Adres MAC jest zblacklistowany!!!! - blokujemy, zostalo {} czasu", 5000 - time_diff);
								}
							} 	
						}

					} 
					else {
						checkMap.put(srcMac, new MacAddressInfo(1, actual_time));
						
						for (String macAddress : blacklistMap.keySet()) { // sprawdzamy wszytskie wpisy w tablicy blacklistujacej nie tylko dla maca tego
							long time_diff = System.currentTimeMillis() - blacklistMap.get(srcMac).getBlacklistTimer();
							MacAddressBlacklist info = blacklistMap.get(macAddress);
							
							if (time_diff > 5000) {
								logger.info("Odblacklistowujemy :D");
								blacklistMap.remove(srcMac);
							} else {
								logger.info("Adres MAC jest zblacklistowany!!!! - blokujemy, zostalo {} czasu", 5000 - time_diff);
							}
						} 	
						
						//wypisanie danych struktury
//						logger.info("Adres MAC(pierwsze wystapienie): {}", srcMac);
//						logger.info("Counter: {}", checkMap.get(srcMac).getCounter());
//						logger.info("Timestamp: {}", checkMap.get(srcMac).getTimestamp());
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
