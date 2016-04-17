// Much of this code was directly inspired by https://github.com/mikeflynn/go-dash-button
// Lacking a license on that project, I can't really think of anything better than a
// notice about this in the source code.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	configPath = flag.String("config", "", "The configuration file")
)

func main() {
	flag.Parse()
	if *configPath == "" {
		log.Fatalln("expected a config, but none was given")
	}

	config, err := LoadConfigFromFile(*configPath)
	boomtown(err)

	ifaces, err := net.Interfaces()
	boomtown(err)

	log.Println("got interfaces")

	var wg sync.WaitGroup

	for _, iface := range ifaces {
		wg.Add(1)

		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface, config); err != nil {
				log.Printf("interface %v: %v\n", iface.Name, err)
			}
		}(iface)
	}

	wg.Wait()
}

func scan(iface *net.Interface, config *Config) error {
	var addr *net.IPNet

	addrs, err := iface.Addrs()
	boomtown(err)

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				addr = &net.IPNet{IP: ip4, Mask: ipnet.Mask[len(ipnet.Mask)-4:]}
				break
			}
		}
	}

	if addr == nil {
		return errors.New("no good IP network found")
	}
	if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	}
	log.Printf("Using network range %v for interface %v\n", addr, iface.Name)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	boomtown(err)
	defer handle.Close()

	stop := make(chan struct{})
	readARP(handle, iface, stop, config)
	defer close(stop)

	return err
}

func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}, config *Config) {
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

			if !net.IP(arp.SourceProtAddress).Equal(net.ParseIP("0.0.0.0")) {
				continue
			}

			found := false
			for _, btn := range config.Buttons {
				if net.HardwareAddr(arp.SourceHwAddress).String() == btn.Address {
					found = true
					log.Printf("received ping for button '%v'", btn.Name)

					if btn.URL != "" && btn.Method != "" {
						go dispatchHTTPRequestForBtn(&btn)
					}
				}
			}

			if !found {
				log.Printf("received ping for unknown MAC addr: %v\n", net.HardwareAddr(arp.SourceHwAddress))
			}
		}
	}
}

func dispatchHTTPRequestForBtn(btn *Button) {
	var buf *bytes.Reader

	if btn.Method == "POST" {
		body, err := json.Marshal(btn.Body)
		if err != nil {
			log.Fatalln(err)
		}

		buf = bytes.NewReader(body)
	}

	req, err := http.NewRequest(btn.Method, btn.URL, buf)
	if err != nil {
		log.Fatalln(err)
	}

	client := &http.Client{}

	for hdr, val := range btn.Headers {
		req.Header.Add(hdr, val)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("%v %v returned status %q\n", req.Method, req.URL, resp.Status)
	}
}

func boomtown(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
