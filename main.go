// main entrypoint
package main

import (
	"log"
	"net"
	"os"
	"strings"
)

var port int16 = 8053

func main() {
	// Example: configure allowed secondaries and TSIG keys (edit as needed)
	setupAXFR(
		[]string{"127.0.0.1"}, // allowed secondary IPs
		[]tsigKey{{
			Name:      "axfr-key.",
			Secret:    "dGVzdGtleQ==", // base64 for 'testkey'
			Algorithm: TSIG_HMAC_SHA256,
		}},
	)
	// load zone file
	err := load_zone("zone.txt")
	if err != nil {
		log.Println("could not load zone: ", err)
	}

	// start dns server (udp 53)
	go start_dns(port)

	// start tcp dns server (AXFR/TSIG)
	go start_tcp_dns(port)

	// start web ui (8080)
	start_web()
}

func start_dns(port int16) {
	addr := net.UDPAddr{Port: int(port), IP: net.IPv4zero}
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
			log.Println("error reading UDP: ", err)
			continue
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Println("Recovered from panic in handle_query:", r)
				}
			}()
			handle_query(conn, client, buf[:n])
		}()
	}
}

// findZoneRecords returns records for exact or wildcard matches
func findZoneRecords(name string) []rr {
	if recs, ok := zone[name]; ok && len(recs) > 0 {
		return recs
	}
	// Try wildcard matches
	labels := strings.Split(name, ".")
	// Remove trailing empty label from split (from trailing dot)
	if len(labels) > 0 && labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	for i := 0; i < len(labels)-1; i++ {
		wildcardLabels := make([]string, len(labels))
		copy(wildcardLabels, labels)
		wildcardLabels[i] = "*"
		wildcardName := strings.Join(wildcardLabels, ".") + "."
		if recs, ok := zone[wildcardName]; ok && len(recs) > 0 {
			return recs
		}
	}
	return nil
}

func handle_query(conn *net.UDPConn, client *net.UDPAddr, data []byte) {
	logAnalyticsEvent("request")
	hdr, q, err := parse_dns_msg(data)
	if err != nil {
		logAnalyticsEvent("error")
		return
	}
	if q.Class != class_in {
		logAnalyticsEvent("error")
		return
	}
	name := q.Name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	answers := findZoneRecords(name)
	if len(answers) == 0 {
		logAnalyticsEvent("notfound")
	}
	// if the answer is from a wildcard, set the owner name to the query name
	var fixedAnswers []rr
	for _, r := range answers {
		if r.Name != name {
			r2 := r
			r2.Name = name
			fixedAnswers = append(fixedAnswers, r2)
		} else {
			fixedAnswers = append(fixedAnswers, r)
		}
	}
	resp, err := build_response(hdr, q, fixedAnswers, nil)
	if err != nil {
		logAnalyticsEvent("error")
		return
	}
	conn.WriteToUDP(resp, client)
}
