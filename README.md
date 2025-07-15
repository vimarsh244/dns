# dns server

making simple authoritative dns server in go

go is such a simple and nice language, really enhoying learning and writing it so far

## how to run

1. run the server (see the port in main.go):

```sh
sudo go run .
# need sudo if using port 53 
```


2. test dns:

```sh
dig @127.0.0.1 domain.com A
# dig @127.0.0.1 -p 8053 domain.com A
```

3. open the web ui: - doesn't work yet todo

http://localhost:8080/

login with user `admin` and password 

## notes
- records are stored in zone.txt
- web ui mnaking very simple one for add/remove records
- goal is no external libraries 

## supported record types
- A
- NS
- CNAME
TODOs: txt, mx, aaaa (ipv6 ),  (these should be enuf)