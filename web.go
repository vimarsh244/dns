// web interface for managing dns records
package main

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"rrValue": func(r rr) string {
		switch r.type_ {
		case type_a:
			if len(r.rdata) == 4 {
				return net.IP(r.rdata).String()
			}
		case type_ns, type_cname:
			return decode_name(r.rdata)
		}
		return "?"
	},
}).ParseGlob("templates/*.html"))

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
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		delete(zone, name)
		save_zone("zone.txt")
		http.Redirect(w, r, "/", 303)
		return
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
			rrec.name = name
			rrec.class = class_in
			rrec.ttl = uint32(ttl)
			switch strings.ToUpper(type_) {
			case "A":
				rrec.type_ = type_a
				ip := net.ParseIP(value).To4()
				if ip != nil {
					rrec.rdata = ip
					zone[name] = append(zone[name], rrec)
				}
			case "NS":
				rrec.type_ = type_ns
				buf := &strings.Builder{}
				for _, label := range strings.Split(value, ".") {
					if label == "" {
						continue
					}
					buf.WriteByte(byte(len(label)))
					buf.WriteString(label)
				}
				buf.WriteByte(0)
				rrec.rdata = []byte(buf.String())
				zone[name] = append(zone[name], rrec)
			case "CNAME":
				rrec.type_ = type_cname
				buf := &strings.Builder{}
				for _, label := range strings.Split(value, ".") {
					if label == "" {
						continue
					}
					buf.WriteByte(byte(len(label)))
					buf.WriteString(label)
				}
				buf.WriteByte(0)
				rrec.rdata = []byte(buf.String())
				zone[name] = append(zone[name], rrec)
			}
			save_zone("zone.txt")
		}
		http.Redirect(w, r, "/", 303)
		return
	}
	data := struct {
		Records map[string][]rr
	}{zone}
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
