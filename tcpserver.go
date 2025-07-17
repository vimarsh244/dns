// tcpserver.go: TCP DNS server for AXFR/TSIG
package main

import (
	"log"
	"net"
)

func start_tcp_dns(port int16) {
	addr := net.TCPAddr{Port: int(port), IP: net.IPv4zero}
	ln, err := net.ListenTCP("tcp", &addr)
	// if err != nil {
	// addr := ":8053" // match UDP port for simplicity
	// ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Println("could not bind tcp :", addr, err)
		return
	}
	log.Println("dns server started on tcp :", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("tcp accept error:", err)
			continue
		}
		go func(c net.Conn) {
			remoteIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			handleAXFR(c, remoteIP)
		}(conn)
	}
}
