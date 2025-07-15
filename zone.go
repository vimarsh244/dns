// zone file and in-memory record management
package main

import (
    "bufio"
    "net"
    "os"
    "strconv"
    "strings"
    "log"
)

// in-memory zone map
var zone = make(map[string][]rr)

// load zone file
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
        parts := strings.Fields(line)
        if len(parts) < 4 {
            continue
        }
        name := parts[0]
        if !strings.HasSuffix(name, ".") {
            name += "."
        }
        type_ := strings.ToUpper(parts[1])
        value := parts[2]
        ttl, _ := strconv.Atoi(parts[3])
        var r rr
        r.name = name
        r.class = class_in
        r.ttl = uint32(ttl)
        switch type_ {
        case "A":
            r.type_ = type_a
            ip := net.ParseIP(value).To4()
            if ip == nil {
                continue
            }
            r.rdata = ip
        case "NS":
            r.type_ = type_ns
            // ns rdata is domain name
            buf := &strings.Builder{}
            for _, label := range strings.Split(value, ".") {
                buf.WriteByte(byte(len(label)))
                buf.WriteString(label)
            }
            buf.WriteByte(0)
            r.rdata = []byte(buf.String())
        case "CNAME":
            r.type_ = type_cname
            buf := &strings.Builder{}
            for _, label := range strings.Split(value, ".") {
                buf.WriteByte(byte(len(label)))
                buf.WriteString(label)
            }
            buf.WriteByte(0)
            r.rdata = []byte(buf.String())
        }
        zone[name] = append(zone[name], r)
        // Debug: log the loaded record
        log.Printf("Loaded record: name=%s type=%d class=%d ttl=%d rdata=%v", r.name, r.type_, r.class, r.ttl, r.rdata)
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
            switch r.type_ {
            case type_a:
                typ = "A"
                val = net.IP(r.rdata).String()
            case type_ns:
                typ = "NS"
                val = decode_name(r.rdata)
            case type_cname:
                typ = "CNAME"
                val = decode_name(r.rdata)
            }
            if typ != "" {
                f.WriteString(name + " " + typ + " " + val + " " + strconv.Itoa(int(r.ttl)) + "\n")
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
