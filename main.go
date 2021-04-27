package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

func main() {
	ifaces, err := net.Interfaces()
	devs, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func(iface net.Interface, devs []pcap.Interface) {
			if err := scan(&iface, devs); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface, devs)
	}

	wg.Wait()
}

func scan(iface *net.Interface, devs []pcap.Interface) error {
	addr, err := GetIPV4Addr(iface)
	if err != nil {
		return err
	}

	if addr.IP[0] == 127 {
		return fmt.Errorf("skip localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff { // !(addr.Mask[0] == 0xff && addr.Mask[1] == 0xff)
		return fmt.Errorf("mask means network is too large")
	}

	var devName string

	switch runtime.GOOS {
	case "windows":
		for _, dev := range devs {
			if strings.Contains(fmt.Sprint(dev.Addresses), fmt.Sprint(addr.IP)) {
				devName = dev.Name
			}
		}
	default:
		devName = iface.Name
	}


	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	handle, err := pcap.OpenLive(devName, 65535, true, pcap.BlockForever)

	if err != nil {
		return err
	}
	defer handle.Close()

	stop := make(chan bool)
	defer close(stop)
	go readArp(handle, iface, stop)

	for {
		if err := writeArp(handle, iface, addr); err != nil {
			log.Printf("error writing packets on %v: %v", iface.Name, err)
			return err
		}

		time.Sleep(10 * time.Second)
	}
}

func readArp(handle *pcap.Handle, iface *net.Interface, stop <-chan bool) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet

		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)

			if arp.Operation != layers.ARPReply || bytes.Equal(iface.HardwareAddr, arp.SourceHwAddress) { // this is a packet i sent
				continue
			}

			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

func writeArp(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6,
		ProtAddressSize: 4,
		Operation: layers.ARPRequest,
		SourceHwAddress: iface.HardwareAddr,
		SourceProtAddress: addr.IP,
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	for _, ip := range ips(addr) {
		arp.DstProtAddress = ip
		if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
			return err
		}
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func ips(addr *net.IPNet) []net.IP {
	result := make([]net.IP, 0)
	num := binary.BigEndian.Uint32(addr.IP)
	mask := binary.BigEndian.Uint32(addr.Mask)

	network := num & mask
	broadcast := network | ^mask

	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		result = append(result, buf[:])
	}

	return result
}

func GetIPV4Addr(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()

	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				return &net.IPNet{
					IP:   ipv4,
					Mask: ipNet.Mask[len(ipNet.Mask)-4:],
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("cannot get ipv4 address of interface %v", iface.Name)
}