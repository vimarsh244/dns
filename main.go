// main entrypoint
package main

import (
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	// load zone file
	err := load_zone("zone.txt")
	if err != nil {
		log.Fatal("could not load zone: ", err)
	}

	// start dns server (udp 53)
	go start_dns()

	// start web ui (8080)
	start_web()
}

func start_dns() {
	addr := net.UDPAddr{Port: 8053, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Println("could not bind udp : ", addr.Port, err)
		os.Exit(1)
	}
	log.Println("dns server started on udp : ", addr.Port)
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go handle_query(conn, client, buf[:n])
	}
}

func handle_query(conn *net.UDPConn, client *net.UDPAddr, data []byte) {
	hdr, q, err := parse_dns_msg(data)
	if err != nil {
		return
	}
	// Allow other query types to pass through for zone lookup
	if q.Class != class_in {
		return
	}
	name := q.Name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	answers := zone[name]
	resp, err := build_response(hdr, q, answers, nil)
	if err != nil {
		return
	}
	conn.WriteToUDP(resp, client)
}
