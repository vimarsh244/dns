// dns types and constants
package main

// header flag masks
const (
	qr_mask     = 1 << 15
	opcode_mask = 0x7800
	aa_mask     = 1 << 10
	rcode_mask  = 0x000f
)

// rr types
const (
	type_a     = 1
	type_ns    = 2
	type_soa   = 6
	type_cname = 5
	type_mx    = 15
	type_aaaa  = 28
	type_txt   = 16
	class_in   = 1
)

// resource record struct
type rr struct {
	Name  string
	Type_ uint16
	Class uint16
	TTL   uint32
	Rdata []byte // for a: 4 bytes, for others: whatever
	// For SOA only (optional, for convenience)
	SOA *soaRdata // nil unless Type_ == type_soa
}

// SOA RDATA struct (for convenience)
type soaRdata struct {
	MName   string // primary NS
	RName   string // responsible party (mailbox, with . for @)
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

// dns header struct
type dns_header struct {
	Id      uint16
	Flags   uint16
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

// dns question struct
type dns_question struct {
	Name  string
	Type_ uint16
	Class uint16
}
