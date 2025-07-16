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

4. Files it creates

zone.txt
```
# zone TYPE data TTL
domain.com. A 192.0.2.123 3600
```

analytics.log

```
{"type":"request","timestamp":"2025-07-16T14:30:17.430353211Z"}
```


## notes
- records are stored in zone.txt
- web ui mnaking very simple one for add/remove records
- goal is no external libraries 

- no caching or anything 
- currently wildcard support for domain is implemented in such a hacky way - patched upon patch to check *. and if it wildcard then subdomain should return with subdomain - like this isnt a good way but, only i am using it so like fine?


## supported record types
- A
- NS
- CNAME
- TXT
- AAAA
TODOs:  mx,  (these should be enuf)