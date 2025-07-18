// web interface for managing dns records
package main

import (
	"bytes"
	"encoding/binary"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt" // literally only needef ro pass
)

var portweb int16 = 3000

var templates *template.Template

func init() {
	funcMap := template.FuncMap{
		"rrValue": func(r rr) string {
			switch r.Type_ {
			case type_a:
				if len(r.Rdata) == 4 {
					return net.IP(r.Rdata).String()
				}
			case type_aaaa:
				if len(r.Rdata) == 16 {
					return net.IP(r.Rdata).String()
				}
			case type_ns, type_cname:
				return decode_name(r.Rdata)
			case type_txt:
				if len(r.Rdata) > 1 {
					// Display quoted TXT value for correct deletion
					return quoteTXT(string(r.Rdata[1:]))
				}
			case type_mx:
				if len(r.Rdata) > 2 {
					preference := int(r.Rdata[0])<<8 | int(r.Rdata[1])
					exchange := decode_name(r.Rdata[2:])
					return strconv.Itoa(preference) + " " + exchange
				}
			case type_soa:
				if r.SOA != nil {
					return r.SOA.MName + " " + r.SOA.RName + " " +
						strconv.FormatUint(uint64(r.SOA.Serial), 10) + " " +
						strconv.FormatUint(uint64(r.SOA.Refresh), 10) + " " +
						strconv.FormatUint(uint64(r.SOA.Retry), 10) + " " +
						strconv.FormatUint(uint64(r.SOA.Expire), 10) + " " +
						strconv.FormatUint(uint64(r.SOA.Minimum), 10)
				}
			}
			return "?"
		},
		"unquoteTXT": unquoteTXT,
		"split":      strings.Split,
	}
	// Ensure layout.html is the base and index.html is available as a named template
	templates = template.Must(template.New("layout.html").Funcs(funcMap).ParseFiles(
		"templates/layout.html",
		"templates/index.html",
		// "templates/ignoreiglogin.html",
	))
}

// password hash file (bcrypt hash)
var passfile = "admin.pass"
var password_hash []byte

func start_web() {
	// load password hash
	hash, err := os.ReadFile(passfile)
	if err != nil {
		log.Println("could not read admin.pass: ", err)
		password_hash = nil
	} else {
		password_hash = hash
	}
	http.HandleFunc("/", basic_auth(handle_index))
	log.Println("web ui on :{portweb}", portweb)
	err = http.ListenAndServe(":"+strconv.Itoa(int(portweb)), nil)
	if err != nil {
		log.Println("web server error: ", err)
	}
}

func handle_index(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && r.FormValue("del") != "" {
		name := r.FormValue("del")
		delTypeStr := r.FormValue("delType")
		delValueStr := r.FormValue("delValue")

		if !strings.HasSuffix(name, ".") {
			name += "."
		}

		records := zone[name]
		var updatedRecords []rr

		var delType uint16
		switch strings.ToUpper(delTypeStr) {
		case "A":
			delType = type_a
		case "AAAA":
			delType = type_aaaa
		case "NS":
			delType = type_ns
		case "CNAME":
			delType = type_cname
		case "TXT":
			delType = type_txt
		case "MX":
			delType = type_mx
		case "SOA":
			delType = type_soa
		default:
			log.Printf("Warning: Unknown record type \"%s\" for deletion of %s", delTypeStr, name)
			updatedRecords = records
		}

		var delRdata []byte
		switch delType {
		case type_a:
			ip := net.ParseIP(delValueStr).To4()
			if ip != nil {
				delRdata = ip
			} else {
				log.Printf("Warning: Invalid IP address \"%s\" for A record deletion of %s", delValueStr, name)
				updatedRecords = records
			}
		case type_aaaa:
			ip := net.ParseIP(delValueStr).To16()
			if ip != nil && ip.To4() == nil {
				delRdata = ip
			} else {
				log.Printf("Warning: Invalid IPv6 address \"%s\" for AAAA record deletion of %s", delValueStr, name)
				updatedRecords = records
			}
		case type_ns, type_cname:
			if !strings.HasSuffix(delValueStr, ".") {
				delValueStr += "."
			}
			buf := &strings.Builder{}
			for _, label := range strings.Split(delValueStr, ".") {
				if label == "" {
					continue
				}
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
			buf.WriteByte(0)
			delRdata = []byte(buf.String())
		case type_txt:
			txtVal := unquoteTXT(delValueStr)
			if len(txtVal) > 255 {
				log.Printf("Warning: TXT value too long for deletion of %s", name)
				updatedRecords = records
			} else {
				delRdata = append([]byte{byte(len(txtVal))}, []byte(txtVal)...)
			}
		case type_mx:
			parts := strings.Fields(delValueStr)
			if len(parts) == 2 {
				preference, err := strconv.Atoi(parts[0])
				if err != nil {
					log.Printf("Warning: Invalid preference for MX record deletion of %s", name)
					updatedRecords = records
					break
				}
				exchange := parts[1]
				if !strings.HasSuffix(exchange, ".") {
					exchange += "."
				}
				buf := &bytes.Buffer{}
				binary.Write(buf, binary.BigEndian, uint16(preference))
				write_name(buf, exchange)
				delRdata = buf.Bytes()
			} else {
				log.Printf("Warning: Invalid MX value for deletion of %s", name)
				updatedRecords = records
			}
		case type_soa:
			parts := strings.Fields(delValueStr)
			if len(parts) == 7 {
				mname := parts[0]
				rname := parts[1]
				serial, _ := strconv.ParseUint(parts[2], 10, 32)
				refresh, _ := strconv.ParseUint(parts[3], 10, 32)
				retry, _ := strconv.ParseUint(parts[4], 10, 32)
				expire, _ := strconv.ParseUint(parts[5], 10, 32)
				minimum, _ := strconv.ParseUint(parts[6], 10, 32)

				if !strings.HasSuffix(mname, ".") {
					mname += "."
				}
				if !strings.HasSuffix(rname, ".") {
					rname += "."
				}

				buf := &bytes.Buffer{}
				write_name(buf, mname)
				write_name(buf, rname)
				binary.Write(buf, binary.BigEndian, uint32(serial))
				binary.Write(buf, binary.BigEndian, uint32(refresh))
				binary.Write(buf, binary.BigEndian, uint32(retry))
				binary.Write(buf, binary.BigEndian, uint32(expire))
				binary.Write(buf, binary.BigEndian, uint32(minimum))
				delRdata = buf.Bytes()
			} else {
				log.Printf("Warning: Invalid SOA value for deletion of %s", name)
				updatedRecords = records
			}
		}
		for _, r := range records {
			if !(r.Name == name && r.Type_ == delType && bytes.Equal(r.Rdata, delRdata)) {
				updatedRecords = append(updatedRecords, r)
			}
		}
		if len(updatedRecords) == 0 {
			delete(zone, name)
		} else {
			zone[name] = updatedRecords
		}
		save_zone("zone.txt")
	}
	if r.Method == "POST" {
		name := r.FormValue("name")
		type_ := r.FormValue("type")
		value := r.FormValue("value")
		ttl, _ := strconv.Atoi(r.FormValue("ttl"))
		if name != "" && type_ != "" && ttl > 0 {
			if !strings.HasSuffix(name, ".") {
				name += "."
			}
			if (strings.ToUpper(type_) == "NS" || strings.ToUpper(type_) == "CNAME") && !strings.HasSuffix(value, ".") {
				value += "."
			}
			var rrec rr
			rrec.Name = name
			rrec.Class = class_in
			rrec.TTL = uint32(ttl)
			switch strings.ToUpper(type_) {
			case "A":
				rrec.Type_ = type_a
				ip := net.ParseIP(value).To4()
				if ip != nil {
					rrec.Rdata = ip
					zone[name] = append(zone[name], rrec)
				}
			case "AAAA":
				rrec.Type_ = type_aaaa
				ip := net.ParseIP(value).To16()
				if ip != nil && ip.To4() == nil {
					rrec.Rdata = ip
					zone[name] = append(zone[name], rrec)
				}
			case "NS":
				rrec.Type_ = type_ns
				buf := &strings.Builder{}
				for _, label := range strings.Split(value, ".") {
					if label == "" {
						continue
					}
					buf.WriteByte(byte(len(label)))
					buf.WriteString(label)
				}
				buf.WriteByte(0)
				rrec.Rdata = []byte(buf.String())
				zone[name] = append(zone[name], rrec)
			case "CNAME":
				rrec.Type_ = type_cname
				buf := &strings.Builder{}
				for _, label := range strings.Split(value, ".") {
					if label == "" {
						continue
					}
					buf.WriteByte(byte(len(label)))
					buf.WriteString(label)
				}
				buf.WriteByte(0)
				rrec.Rdata = []byte(buf.String())
				zone[name] = append(zone[name], rrec)
			case "TXT":
				rrec.Type_ = type_txt
				txtVal := unquoteTXT(value)
				if len(txtVal) <= 255 {
					rrec.Rdata = append([]byte{byte(len(txtVal))}, []byte(txtVal)...)
					zone[name] = append(zone[name], rrec)
				}
			case "MX":
				rrec.Type_ = type_mx
				preference, err := strconv.Atoi(r.FormValue("preference"))
				if err != nil {
					log.Printf("Warning: Invalid preference for MX record: %v", err)
					break
				}
				exchange := r.FormValue("exchange")
				if !strings.HasSuffix(exchange, ".") {
					exchange += "."
				}
				buf := &bytes.Buffer{}
				binary.Write(buf, binary.BigEndian, uint16(preference))
				write_name(buf, exchange)
				rrec.Rdata = buf.Bytes()
				zone[name] = append(zone[name], rrec)
			case "SOA":
				rrec.Type_ = type_soa
				mname := r.FormValue("mname")
				rname := r.FormValue("rname")
				serial, _ := strconv.ParseUint(r.FormValue("serial"), 10, 32)
				refresh, _ := strconv.ParseUint(r.FormValue("refresh"), 10, 32)
				retry, _ := strconv.ParseUint(r.FormValue("retry"), 10, 32)
				expire, _ := strconv.ParseUint(r.FormValue("expire"), 10, 32)
				minimum, _ := strconv.ParseUint(r.FormValue("minimum"), 10, 32)

				if !strings.HasSuffix(mname, ".") {
					mname += "."
				}
				if !strings.HasSuffix(rname, ".") {
					rname += "."
				}

				buf := &bytes.Buffer{}
				write_name(buf, mname)
				write_name(buf, rname)
				binary.Write(buf, binary.BigEndian, uint32(serial))
				binary.Write(buf, binary.BigEndian, uint32(refresh))
				binary.Write(buf, binary.BigEndian, uint32(retry))
				binary.Write(buf, binary.BigEndian, uint32(expire))
				binary.Write(buf, binary.BigEndian, uint32(minimum))
				rrec.Rdata = buf.Bytes()
				rrec.SOA = &soaRdata{
					MName:   mname,
					RName:   rname,
					Serial:  uint32(serial),
					Refresh: uint32(refresh),
					Retry:   uint32(retry),
					Expire:  uint32(expire),
					Minimum: uint32(minimum),
				}
				zone[name] = append(zone[name], rrec)
			}
			save_zone("zone.txt")
		}
	}
	// Update analytics summary before rendering
	updateAnalyticsSummary()
	stats, _ := readAnalyticsSummary()

	// Categorize records by type for the template
	categorizedRecords := make(map[string]map[string][]rr)
	// Ensure all desired record types are present in the map for the UI
	recordTypes := []string{"A", "AAAA", "NS", "CNAME", "TXT", "MX", "SOA"}
	for _, t := range recordTypes {
		categorizedRecords[t] = make(map[string][]rr)
	}

	for name, records := range zone {
		for _, record := range records {
			var typeStr string
			switch record.Type_ {
			case type_a:
				typeStr = "A"
			case type_aaaa:
				typeStr = "AAAA"
			case type_ns:
				typeStr = "NS"
			case type_cname:
				typeStr = "CNAME"
			case type_txt:
				typeStr = "TXT"
			case type_mx:
				typeStr = "MX"
			case type_soa:
				typeStr = "SOA"
			default:
				typeStr = "Other"
			}
			if _, ok := categorizedRecords[typeStr]; !ok {
				categorizedRecords[typeStr] = make(map[string][]rr)
			}
			categorizedRecords[typeStr][name] = append(categorizedRecords[typeStr][name], record)
		}
	}

	data := struct {
		Records   map[string]map[string][]rr
		Analytics map[string]map[string]int
	}{categorizedRecords, stats}

	// Debug: Log the records and analytics being passed to the template
	log.Printf("DEBUG: Web UI Records: %+v\n", data.Records)
	log.Printf("DEBUG: Analytics: %+v\n", data.Analytics)

	templates.ExecuteTemplate(w, "layout.html", data)
}

// basic auth middleware
func basic_auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || bcrypt.CompareHashAndPassword(password_hash, []byte(pass)) != nil {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"dns admin\"")
			w.WriteHeader(401)
			w.Write([]byte("unauthorized\n"))
			return
		}
		next(w, r)
	}
}

func quoteTXT(s string) string {
	return `"` + s + `"`
}

func unquoteTXT(s string) string {
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}