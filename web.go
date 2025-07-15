// web interface for managing dns records
package main

import (
	"bytes"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var templates *template.Template

func init() {
	funcMap := template.FuncMap{
		"rrValue": func(r rr) string {
			switch r.Type_ {
			case type_a:
				if len(r.Rdata) == 4 {
					return net.IP(r.Rdata).String()
				}
			case type_ns, type_cname:
				return decode_name(r.Rdata)
			}
			return "?"
		},
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
		log.Fatal("could not read admin.pass: ", err)
	}
	password_hash = hash

	http.HandleFunc("/", basic_auth(handle_index))
	log.Println("web ui on :8080")
	http.ListenAndServe(":8080", nil)
}

func handle_index(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && r.FormValue("del") != "" {
		name := r.FormValue("del")
		delTypeStr := r.FormValue("delType")
		delValueStr := r.FormValue("delValue")

		if !strings.HasSuffix(name, ".") {
			name += "."
		}

		// Get existing records for the name
		records := zone[name]
		var updatedRecords []rr

		var delType uint16
		switch strings.ToUpper(delTypeStr) {
		case "A":
			delType = type_a
		case "NS":
			delType = type_ns
		case "CNAME":
			delType = type_cname
		default:
			log.Printf("Warning: Unknown record type \"%s\" for deletion of %s", delTypeStr, name)
			// keeping all existing records if type is unknown, essentially skipping deletion.
			updatedRecords = records
		}

		var delRdata []byte
		// convering delValueStr to []byte based on delType for comparison
		switch delType {
		case type_a:
			ip := net.ParseIP(delValueStr).To4()
			if ip != nil {
				delRdata = ip
			} else {
				log.Printf("Warning: Invalid IP address \"%s\" for A record deletion of %s", delValueStr, name)
				updatedRecords = records // Cannot parse value, skip deletion
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
		}

		// iterating through existing records and keep only those that don't match the one to be deleted
		for _, r := range records {
			// Compare Name, Type_, and Rdata to find the specific record to delete
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
		// No redirect, continue to render the page
	}
	if r.Method == "POST" {
		name := r.FormValue("name")
		type_ := r.FormValue("type")
		value := r.FormValue("value")
		ttl, _ := strconv.Atoi(r.FormValue("ttl"))
		if name != "" && type_ != "" && value != "" && ttl > 0 {
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
			}
			save_zone("zone.txt")
		}
	}
	data := struct {
		Records map[string][]rr
	}{zone}

	// Debug: Log the records being passed to the template
	log.Printf("DEBUG: Web UI Records: %+v\n", data.Records)

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
