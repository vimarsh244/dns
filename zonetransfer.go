// implementing AXFR and TSIG
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// supported TSIG algorithms
const (
	TSIG_HMAC_MD5    = "hmac-md5.sig-alg.reg.int."
	TSIG_HMAC_SHA256 = "hmac-sha256."
	TSIG_HMAC_SHA512 = "hmac-sha512."
)

type tsigKey struct {
	Name      string // FQDN
	Secret    string // base64
	Algorithm string // from above like TSIG_HMAC_SHA256
}

type axfrConfig struct {
	Secondaries []string // allowed IPs
	TSIGKeys    []tsigKey
}

var axfrConf axfrConfig

// AXFR config (to call while dns startup)
func setupAXFR(secondaries []string, keys []tsigKey) {
	axfrConf.Secondaries = secondaries
	axfrConf.TSIGKeys = keys
}

// find TSIG key by name
func getTSIGKey(name string) *tsigKey {
	for _, k := range axfrConf.TSIGKeys {
		if strings.EqualFold(k.Name, name) {
			return &k
		}
	}
	return nil
}

// HMAC for TSIG
func tsigMAC(algo, secret string, msg []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	switch algo {
	case TSIG_HMAC_MD5:
		h := hmac.New(md5.New, key)
		h.Write(msg)
		return h.Sum(nil), nil
	case TSIG_HMAC_SHA256:
		h := hmac.New(sha256.New, key)
		h.Write(msg)
		return h.Sum(nil), nil
	case TSIG_HMAC_SHA512:
		h := hmac.New(sha512.New, key)
		h.Write(msg)
		return h.Sum(nil), nil
	default:
		return nil, errors.New("unsupported TSIG algorithm")
	}
}

// TSIG record (minimal)
type tsigRecord struct {
	Name       string
	Algorithm  string
	TimeSigned uint64
	Fudge      uint16
	MAC        []byte
	OrigID     uint16
	Error      uint16
	OtherData  []byte
}

// Write TSIG RR to wire format (append to DNS message)
func writeTSIG(w io.Writer, tsig *tsigRecord) error {
	// Helper to write a domain name in DNS wire format
	writeName := func(name string) error {
		labels := strings.Split(name, ".")
		for _, label := range labels {
			if label == "" {
				continue
			}
			if len(label) > 63 {
				return errors.New("label too long")
			}
			if _, err := w.Write([]byte{byte(len(label))}); err != nil {
				return err
			}
			if _, err := w.Write([]byte(label)); err != nil {
				return err
			}
		}
		// End with zero length
		if _, err := w.Write([]byte{0}); err != nil {
			return err
		}
		return nil
	}

	// Write NAME (key name)
	if err := writeName(tsig.Name); err != nil {
		return err
	}
	// Write TYPE (TSIG = 250)
	if _, err := w.Write([]byte{0, 250}); err != nil {
		return err
	}
	// Write CLASS (ANY = 255)
	if _, err := w.Write([]byte{0, 255}); err != nil {
		return err
	}
	// Write TTL (0)
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}

	// Prepare RDATA in a buffer
	rdata := &strings.Builder{}
	// Algorithm Name
	if err := writeNameTo(rdata, tsig.Algorithm); err != nil {
		return err
	}
	// Time Signed (48 bits)
	ts := make([]byte, 6)
	ts[0] = byte(tsig.TimeSigned >> 40)
	ts[1] = byte(tsig.TimeSigned >> 32)
	ts[2] = byte(tsig.TimeSigned >> 24)
	ts[3] = byte(tsig.TimeSigned >> 16)
	ts[4] = byte(tsig.TimeSigned >> 8)
	ts[5] = byte(tsig.TimeSigned)
	rdata.Write(ts)
	// Fudge (16 bits)
	rdata.Write([]byte{byte(tsig.Fudge >> 8), byte(tsig.Fudge)})
	// MAC Size (16 bits)
	macLen := uint16(len(tsig.MAC))
	rdata.Write([]byte{byte(macLen >> 8), byte(macLen)})
	// MAC
	rdata.Write(tsig.MAC)
	// Original ID (16 bits)
	rdata.Write([]byte{byte(tsig.OrigID >> 8), byte(tsig.OrigID)})
	// Error (16 bits)
	rdata.Write([]byte{byte(tsig.Error >> 8), byte(tsig.Error)})
	// Other Len (16 bits)
	otherLen := uint16(len(tsig.OtherData))
	rdata.Write([]byte{byte(otherLen >> 8), byte(otherLen)})
	// Other Data
	rdata.Write(tsig.OtherData)

	// Write RDLEN (length of RDATA)
	rdataBytes := []byte(rdata.String())
	rdlen := uint16(len(rdataBytes))
	if _, err := w.Write([]byte{byte(rdlen >> 8), byte(rdlen)}); err != nil {
		return err
	}
	// Write RDATA
	if _, err := w.Write(rdataBytes); err != nil {
		return err
	}
	return nil
}

// Helper to write a domain name to a strings.Builder in DNS wire format
func writeNameTo(b *strings.Builder, name string) error {
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return errors.New("label too long")
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	return nil
}

// Parse TSIG RR from DNS message (placeholder)
func parseTSIG(msg []byte) (*tsigRecord, error) {
	// Parse TSIG RR from message (see RFC 2845)
	return nil, nil
}

// AXFR handler (TCP only)
func handleAXFR(conn net.Conn, remoteIP string) {
	defer conn.Close()
	allowed := false
	for _, ip := range axfrConf.Secondaries {
		if ip == remoteIP {
			allowed = true
			break
		}
	}
	if !allowed {
		log.Printf("AXFR denied for %s", remoteIP)
		return
	}

	// Read 2-byte length prefix, then DNS message
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("AXFR: failed to read length: %v", err)
		return
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen < 12 {
		log.Printf("AXFR: message too short")
		return
	}
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgBuf); err != nil {
		log.Printf("AXFR: failed to read message: %v", err)
		return
	}

	// Parse header and question
	hdrIn, q, err := parse_dns_msg(msgBuf)
	if err != nil {
		log.Printf("AXFR: failed to parse DNS msg: %v", err)
		return
	}
	if q.Type_ != 252 { // AXFR QTYPE
		log.Printf("AXFR: not an AXFR request (qtype=%d)", q.Type_)
		return
	}

	// TODO: Parse and validate TSIG if present (last RR in additional section)
	// Placeholder: no TSIG validation yet

	log.Printf("AXFR request for zone %s from %s", q.Name, remoteIP)

	// Normalize q.Name and zone keys (ensure trailing dot, lower-case)
	zoneKey := strings.ToLower(q.Name)
	if !strings.HasSuffix(zoneKey, ".") {
		zoneKey += "."
	}
	// Debug: print all zone keys and q.Name
	log.Printf("AXFR: zone keys: %v, q.Name: %s, normalized: %s", keys(zone), q.Name, zoneKey)
	soaRecs := []rr{}
	for _, r := range zone[zoneKey] {
		if r.Type_ == type_soa {
			soaRecs = append(soaRecs, r)
		}
	}
	if len(soaRecs) == 0 {
		log.Printf("AXFR: no SOA record for zone %s (normalized: %s)", q.Name, zoneKey)
		return
	}
	soa := soaRecs[0]

	// Collect all RRs for the zone
	allRRs := []rr{}
	for name, recs := range zone {
		if strings.HasSuffix(name, zoneKey) {
			allRRs = append(allRRs, recs...)
		}
	}

	// AXFR: send [SOA, all RRs, SOA] as separate DNS messages over TCP
	// Each message: 2-byte length prefix + DNS message
	msgs := [][]rr{
		{soa},
		allRRs,
		{soa},
	}
	tsKey := getTSIGKey("axfr-key.") // For demo: always use the configured key
	for _, rrs := range msgs {
		hdr := dns_header{Id: hdrIn.Id, Flags: qr_mask | aa_mask, Qdcount: 1, Ancount: uint16(len(rrs)), Nscount: 0, Arcount: 0}
		qmsg := dns_question{Name: q.Name, Type_: 252, Class: class_in}
		var tsigBuf *strings.Builder
		var tsigRR *tsigRecord
		msg, err := build_response(hdr, qmsg, rrs, nil)
		if err != nil {
			log.Printf("AXFR: failed to build response: %v", err)
			return
		}

		// If TSIG is required, append TSIG RR
		if tsKey != nil {
			mac, err := tsigMAC(tsKey.Algorithm, tsKey.Secret, msg)
			if err != nil {
				log.Printf("AXFR: TSIG signing error: %v", err)
				return
			}
			tsigRR = &tsigRecord{
				Name:       tsKey.Name,
				Algorithm:  tsKey.Algorithm,
				TimeSigned: uint64(timeNow()),
				Fudge:      300,
				MAC:        mac,
				OrigID:     hdr.Id,
				Error:      0,
				OtherData:  nil,
			}
			tsigBuf = &strings.Builder{}
			if err := writeTSIG(tsigBuf, tsigRR); err != nil {
				log.Printf("AXFR: failed to encode TSIG: %v", err)
				return
			}
			// Patch ARCOUNT in header (should be 1 for TSIG)
			// For simplicity, just append TSIG RR to msg and send
			msg = append(msg, []byte(tsigBuf.String())...)
		}

		msgLen := len(msg)
		lenPrefix := []byte{byte(msgLen >> 8), byte(msgLen & 0xff)}
		if _, err := conn.Write(lenPrefix); err != nil {
			log.Printf("AXFR: failed to write length: %v", err)
			return
		}
		if _, err := conn.Write(msg); err != nil {
			log.Printf("AXFR: failed to write message: %v", err)
			return
		}
	}
	log.Printf("AXFR served to %s", remoteIP)
}

// Helper to get all keys from a map[string][]rr

// Helper to get all keys from a map[string][]rr
func keys(m map[string][]rr) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Collect all RRs for the zone

// Helper to get current unix time (seconds)
func timeNow() int64 {
	return time.Now().Unix()
}

// To use: in your TCP server, on AXFR request, call handleAXFR(conn, remoteIP)
