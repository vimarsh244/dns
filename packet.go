// dns packet parsing and serialization
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"
)

// parse dns message (header + question)
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

// read dns name (labels)
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

// write dns name
func write_name(w *bytes.Buffer, name string) {
	// Remove trailing dot if present, as Split will create an empty label for it,
	// and we'll add the final null byte explicitly.
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	for _, label := range strings.Split(name, ".") {
		w.WriteByte(byte(len(label)))
		w.WriteString(label)
	}
	w.WriteByte(0) // Root label terminator
}

// write rr
func write_rr(w *bytes.Buffer, rr rr) {
	write_name(w, rr.name)
	binary.Write(w, binary.BigEndian, rr.type_)
	binary.Write(w, binary.BigEndian, rr.class)
	binary.Write(w, binary.BigEndian, rr.ttl)
	binary.Write(w, binary.BigEndian, uint16(len(rr.rdata)))
	w.Write(rr.rdata)
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
