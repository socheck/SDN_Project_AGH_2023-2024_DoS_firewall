package pl.edu.agh.kt;



import org.projectfloodlight.openflow.protocol.OFMessage;

import org.projectfloodlight.openflow.types.EthType;

import org.projectfloodlight.openflow.types.IPv4Address;

import org.projectfloodlight.openflow.types.MacAddress;

import org.slf4j.Logger;

import org.slf4j.LoggerFactory;



import net.floodlightcontroller.core.FloodlightContext;

import net.floodlightcontroller.core.IFloodlightProviderService;

import net.floodlightcontroller.packet.ARP;

import net.floodlightcontroller.packet.Ethernet;

import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.packet.TCP;

import net.floodlightcontroller.packet.UDP;



public class PacketExtractor {

	private static final Logger logger = LoggerFactory.getLogger(PacketExtractor.class);

	private FloodlightContext cntx;

	protected IFloodlightProviderService floodlightProvider;

	private Ethernet eth;

	private IPv4 ipv4;

	private ARP arp;

	private TCP tcp;

	private UDP udp;

	private OFMessage msg;



	public PacketExtractor(FloodlightContext cntx, OFMessage msg) {

		this.cntx = cntx;

		this.msg = msg;

	}

	

	public PacketExtractor(FloodlightContext cntx) {

		this.cntx = cntx;

	}



	public PacketExtractor() {

	}



	public void packetExtract(FloodlightContext cntx) {

		this.cntx = cntx;

		extractEth();

	}



	public void extractEth() {

		eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		logger.info("Frame: src mac {}", eth.getSourceMACAddress());

		logger.info("Frame: dst mac {}", eth.getDestinationMACAddress());

		logger.info("Frame: ether_type {}", eth.getEtherType());



		if (eth.getEtherType() == EthType.ARP) {

			arp = (ARP) eth.getPayload();

		}

		if (eth.getEtherType() == EthType.IPv4) {

			ipv4 = (IPv4) eth.getPayload();

		}



	}



	public void extractArp() {

		logger.info("ARP extractor");

	}



	public void extractIp() {

		logger.info("IP extractor");

	}

	

	public int getDstPort() {

		eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		int targetPortNumber = 0;

		

		if (eth.getEtherType() == EthType.IPv4) {

			ipv4 = (IPv4) eth.getPayload();

			targetPortNumber = getHostPortNumberFromIpAddress(ipv4.getDestinationAddress());

		}

		

		if (eth.getEtherType() == EthType.ARP) {

            ARP arp = (ARP) eth.getPayload();

            IPv4Address targetIp;

            

            if (arp.getOpCode() == ARP.OP_REQUEST) {

                targetIp = arp.getTargetProtocolAddress();

                targetPortNumber = getHostPortNumberFromIpAddress(targetIp);

            } else if (arp.getOpCode() == ARP.OP_REPLY){

            	targetIp = arp.getTargetProtocolAddress();

                targetPortNumber = getHostPortNumberFromIpAddress(targetIp);

            }

        }

		

        return targetPortNumber;

	}

	

	public MacAddress getSourceMac() {

		eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		MacAddress macAddress = eth.getSourceMACAddress();

        return macAddress;

	}

	

	 private static int getHostPortNumberFromIpAddress(IPv4Address ipAddress) {

	        String ipAddressStr = ipAddress.toString();

	        int lastOctet = Integer.parseInt(ipAddressStr.substring(ipAddressStr.lastIndexOf('.') + 1));

	        return lastOctet;

    }

}

