# go-dns-server

## how to run

1. generate a bcrypt hash for your admin password:

```go
package main
import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)
func main() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("yourpassword"), bcrypt.DefaultCost)
	fmt.Println(string(hash))
}
```

save the output to a file called `admin.pass` in the project root.

2. run the server (needs sudo for port 53):

```sh
sudo go run .
```

3. test dns:

```sh
dig @127.0.0.1 domain.com A
```

4. open the web ui:

http://localhost:8080/

login with user `admin` and your password (basic auth popup)

## notes
- records are stored in zone.txt
- web ui lets you add/remove records
- only A, NS, CNAME supported
- no external libraries except bcrypt for password hashing
- comments in code are lowercase and rough
