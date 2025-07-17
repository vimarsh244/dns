// dns packet parsing and serialization
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"
)

// parsing dns message (header + question)
func parse_dns_msg(data []byte) (dns_header, dns_question, error) {
	var hdr dns_header
	if len(data) < 12 {
		return hdr, dns_question{}, errors.New("packet too short")
	}
	buf := bytes.NewReader(data)
	binary.Read(buf, binary.BigEndian, &hdr)
	name, err := read_name(buf, data)
	if err != nil {
		return hdr, dns_question{}, err
	}
	var q dns_question
	q.Name = name
	binary.Read(buf, binary.BigEndian, &q.Type_)
	binary.Read(buf, binary.BigEndian, &q.Class)
	return hdr, q, nil
}

// reading dns name (labels)
func read_name(r *bytes.Reader, msg []byte) (string, error) {
	var labels []string
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			break
		}
		buf := make([]byte, b)
		if _, err := r.Read(buf); err != nil {
			return "", err
		}
		labels = append(labels, string(buf))
	}
	return strings.Join(labels, "."), nil
}

// writing dns name
func write_name(w *bytes.Buffer, name string) {
	// Remove trailing dot if present, as Split will create an empty label for it,
	// and we'll add the final null byte explicitly.
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	// strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		w.WriteByte(byte(len(label)))
		w.WriteString(label)
	}
	w.WriteByte(0) // Root label terminator
}

// write rr
func write_rr(w *bytes.Buffer, rr rr) {
	write_name(w, rr.Name)
	binary.Write(w, binary.BigEndian, rr.Type_)
	binary.Write(w, binary.BigEndian, rr.Class)
	binary.Write(w, binary.BigEndian, rr.TTL)
	// For SOA, ensure Rdata is up to date from SOA struct if present
	if rr.Type_ == type_soa && rr.SOA != nil {
		buf := &bytes.Buffer{}
		write_name(buf, rr.SOA.MName)
		write_name(buf, rr.SOA.RName)
		binary.Write(buf, binary.BigEndian, rr.SOA.Serial)
		binary.Write(buf, binary.BigEndian, rr.SOA.Refresh)
		binary.Write(buf, binary.BigEndian, rr.SOA.Retry)
		binary.Write(buf, binary.BigEndian, rr.SOA.Expire)
		binary.Write(buf, binary.BigEndian, rr.SOA.Minimum)
		rr.Rdata = buf.Bytes()
	}
	binary.Write(w, binary.BigEndian, uint16(len(rr.Rdata)))
	w.Write(rr.Rdata)
}

// build dns response
func build_response(hdr dns_header, q dns_question, answers []rr, ns []rr) ([]byte, error) {
	hdr.Flags = qr_mask | aa_mask
	hdr.Qdcount = 1
	hdr.Ancount = uint16(len(answers))
	hdr.Nscount = uint16(len(ns))
	hdr.Arcount = 0
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, hdr)
	write_name(buf, q.Name)
	binary.Write(buf, binary.BigEndian, q.Type_)
	binary.Write(buf, binary.BigEndian, q.Class)
	for _, r := range answers {
		write_rr(buf, r)
	}
	for _, r := range ns {
		write_rr(buf, r)
	}
	log.Printf("DEBUG: DNS Response Packet Length: %d bytes", buf.Len())
	return buf.Bytes(), nil
}
