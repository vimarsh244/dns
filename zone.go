// zone file and in-memory record management
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// in-memory zone map
var zone = make(map[string][]rr)

// load zone file
// parseZoneLine splits a zone file line into fields, handling quoted strings for TXT records
func parseZoneLine(line string) []string {
	var fields []string
	var buf strings.Builder
	inQuotes := false
	escaped := false
	for i, r := range line {
		switch {
		case escaped:
			buf.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
		case r == ' ' || r == '\t':
			if inQuotes {
				buf.WriteRune(r)
			} else if buf.Len() > 0 {
				fields = append(fields, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteRune(r)
		}
		// If last character, flush
		if i == len(line)-1 && buf.Len() > 0 {
			fields = append(fields, buf.String())
		}
	}
	return fields
}

func load_zone(path string) error {

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := parseZoneLine(line)
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		typeStr := strings.ToUpper(parts[1])
		value := parts[2]
		ttl, _ := strconv.Atoi(parts[3])
		var r rr
		r.Name = name
		r.Class = class_in
		r.TTL = uint32(ttl)
		switch typeStr {
		case "A":
			r.Type_ = type_a
			ip := net.ParseIP(value).To4()
			if ip == nil {
				continue
			}
			r.Rdata = ip
		case "AAAA":
			r.Type_ = type_aaaa
			ip := net.ParseIP(value).To16()
			if ip == nil || ip.To4() != nil {
				continue
			}
			r.Rdata = ip
		case "NS":
			r.Type_ = type_ns
			buf := &strings.Builder{}
			labels := strings.Split(value, ".")
			for _, label := range labels {
				if label == "" {
					continue // skip empty labels (from trailing dot)
					//> NS RDATA: A <domain-name> which specifies a host which should be authoritative for the specified class and domain.
					// The domain name must be encoded as a sequence of labels ending with a single zero byte.
				}
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
			buf.WriteByte(0)
			r.Rdata = []byte(buf.String())
		case "CNAME":
			r.Type_ = type_cname
			buf := &strings.Builder{}
			labels := strings.Split(value, ".")
			for _, label := range labels {
				if label == "" {
					continue // skip empty labels (from trailing dot)
				}
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
			buf.WriteByte(0)
			r.Rdata = []byte(buf.String())
		case "TXT":
			r.Type_ = type_txt
			txtVal := unquoteTXT(value)
			if len(txtVal) > 255 {
				continue
			}
			r.Rdata = append([]byte{byte(len(txtVal))}, []byte(txtVal)...)
		case "MX":
			r.Type_ = type_mx
			parts := strings.Fields(value)
			if len(parts) != 2 {
				continue
			}
			preference, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			exchange := parts[1]
			if !strings.HasSuffix(exchange, ".") {
				exchange += "."
			}
			r.Preference = uint16(preference)
			r.Exchange = exchange
			// Also store Rdata for wire format if needed elsewhere, though not strictly for template
			buf := &bytes.Buffer{}
			binary.Write(buf, binary.BigEndian, uint16(preference))
			write_name(buf, exchange)
			r.Rdata = buf.Bytes()
		}
		// SOA support
		if typeStr == "SOA" && len(parts) >= 10 {
			r.Type_ = type_soa
			// SOA: <name> SOA <mname> <rname> <serial> <refresh> <retry> <expire> <minimum> <ttl>
			mname := parts[2]
			rname := parts[3]
			serial, _ := strconv.ParseUint(parts[4], 10, 32)
			refresh, _ := strconv.ParseUint(parts[5], 10, 32)
			retry, _ := strconv.ParseUint(parts[6], 10, 32)
			expire, _ := strconv.ParseUint(parts[7], 10, 32)
			minimum, _ := strconv.ParseUint(parts[8], 10, 32)
			r.TTL = uint32(ttl)
			// Encode SOA RDATA to wire format
			buf := &strings.Builder{}
			labels := strings.Split(mname, ".")
			for _, label := range labels {
				if label == "" {
					continue // skip empty labels (from trailing dot)
				}
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
			buf.WriteByte(0)
			labels = strings.Split(rname, ".")
			for _, label := range labels {
				if label == "" {
					continue // skip empty labels (from trailing dot)
				}
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
			buf.WriteByte(0)
			// 5x 32-bit fields
			rdata := make([]byte, 20)
			put32 := func(i int, v uint32) {
				rdata[i] = byte(v >> 24)
				rdata[i+1] = byte(v >> 16)
				rdata[i+2] = byte(v >> 8)
				rdata[i+3] = byte(v)
			}
			put32(0, uint32(serial))
			put32(4, uint32(refresh))
			put32(8, uint32(retry))
			put32(12, uint32(expire))
			put32(16, uint32(minimum))
			r.Rdata = append([]byte(buf.String()), rdata...)
			r.SOA = &soaRdata{
				MName:   mname,
				RName:   rname,
				Serial:  uint32(serial),
				Refresh: uint32(refresh),
				Retry:   uint32(retry),
				Expire:  uint32(expire),
				Minimum: uint32(minimum),
			}
		}
		zone[name] = append(zone[name], r)
		log.Printf("Loaded record: name=%s type=%d class=%d ttl=%d rdata=%v", r.Name, r.Type_, r.Class, r.TTL, r.Rdata)
	}
	return scanner.Err()
}

// save zone file
func save_zone(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for name, records := range zone {
		for _, r := range records {
			var typ, val string
			switch r.Type_ {
			case type_a:
				typ = "A"
				val = net.IP(r.Rdata).String()
			case type_aaaa:
				typ = "AAAA"
				val = net.IP(r.Rdata).String()
			case type_ns:
				typ = "NS"
				val = decode_name(r.Rdata)
			case type_cname:
				typ = "CNAME"
				val = decode_name(r.Rdata)
			case type_txt:
				typ = "TXT"
				if len(r.Rdata) > 1 {
					val = quoteTXT(string(r.Rdata[1:]))
				}
			case type_mx:
				typ = "MX"
				if len(r.Rdata) > 2 {
					preference := int(r.Rdata[0])<<8 | int(r.Rdata[1])
					exchange := decode_name(r.Rdata[2:])
					val = strconv.Itoa(preference) + " " + exchange
				}
			}
			if r.Type_ == type_soa && r.SOA != nil {
				typ = "SOA"
				val = r.SOA.MName + " " + r.SOA.RName + " " + strconv.FormatUint(uint64(r.SOA.Serial), 10) + " " +
					strconv.FormatUint(uint64(r.SOA.Refresh), 10) + " " +
					strconv.FormatUint(uint64(r.SOA.Retry), 10) + " " +
					strconv.FormatUint(uint64(r.SOA.Expire), 10) + " " +
					strconv.FormatUint(uint64(r.SOA.Minimum), 10)
			}
			if typ != "" {
				f.WriteString(name + " " + typ + " " + val + " " + strconv.Itoa(int(r.TTL)) + "\n")
			}
		}
	}
	return nil
}

// Helper to decode SOA RDATA from wire format

// decode dns name from rdata
func decode_name(data []byte) string {
	var labels []string
	i := 0
	for i < len(data) {
		sz := int(data[i])
		if sz == 0 {
			break
		}
		i++
		labels = append(labels, string(data[i:i+sz]))
		i += sz
	}
	name := strings.Join(labels, ".")
	if name != "" {
		name += "."
	}
	return name
}

// Helper to decode SOA RDATA from wire format
func decode_soa_rdata(data []byte) *soaRdata {
	// mname, rname (domain names), then 5x uint32
	mname, mnameLen := decode_name_from_rdata(data)
	rname, rnameLen := decode_name_from_rdata(data[mnameLen:])
	i := mnameLen + rnameLen

	if len(data) < i+20 {
		return nil
	}
	return &soaRdata{
		MName:   mname,
		RName:   rname,
		Serial:  binary.BigEndian.Uint32(data[i : i+4]),
		Refresh: binary.BigEndian.Uint32(data[i+4 : i+8]),
		Retry:   binary.BigEndian.Uint32(data[i+8 : i+12]),
		Expire:  binary.BigEndian.Uint32(data[i+12 : i+16]),
		Minimum: binary.BigEndian.Uint32(data[i+16 : i+20]),
	}
}

func decode_name_from_rdata(data []byte) (string, int) {
	var labels []string
	i := 0
	for i < len(data) {
		sz := int(data[i])
		if sz == 0 {
			i++
			break
		}
		i++
		labels = append(labels, string(data[i:i+sz]))
		i += sz
	}
	name := strings.Join(labels, ".")
	if name != "" {
		name += "."
	}
	return name, i
}
