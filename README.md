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
{"type":"request","name":"www.vimarsh.cc CNAME IN","timestamp":"2025-07-18T07:48:26.359834317Z"}
```


## notes
- records are stored in zone.txt
- web ui mnaking very simple one for add/remove records
- goal is no external libraries 

- no caching or anything 
- currently wildcard support for domain is implemented in such a hacky way - patched upon patch to check *. and if it wildcard then subdomain should return with subdomain - like this isnt a good way but, only i am using it so like fine?

- analytics is implemented in a very simple way, just logging events to a file, and then reading them back to display on the web ui, Everytime a request is made, it logs the event with type "request", and if an error occurs, it logs "error" or "notfound" as appropriate. and then on webui when someone opens page it reads compiles into summary and then displays it on the web ui
- probably will fail when analytics file gets a couple megs

- axfr implementation is kind of there, but verification with hmac rfc and keys is not working - essentially this will proeprly send the zone file and updating of SOA record as well. But verification before sending with tsig keys is not wokrking yet


## supported record types
- A
- NS
- CNAME
- TXT
- AAAA
- MX
TODOs:  PTR and SRV record (mostly wont do) (these should be enuf)

https://www.cloudflare.com/learning/dns/dns-records/ 
cloudflare has listed a lot of records but i dont think we need those - txt records are enough for most verification nowadays