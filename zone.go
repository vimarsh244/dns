// zone file and in-memory record management
package main

import (
	"bufio"
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

func unquoteTXT(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, "\\\"", "\"")
}

func quoteTXT(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
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
			for _, label := range strings.Split(value, ".") {
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
			buf.WriteByte(0)
			r.Rdata = []byte(buf.String())
		case "CNAME":
			r.Type_ = type_cname
			buf := &strings.Builder{}
			for _, label := range strings.Split(value, ".") {
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
			}
			if typ != "" {
				f.WriteString(name + " " + typ + " " + val + " " + strconv.Itoa(int(r.TTL)) + "\n")
			}
		}
	}
	return nil
}

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
	return strings.Join(labels, ".")
}
