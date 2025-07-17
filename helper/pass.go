package main
import (
	"fmt"
	"os"
	"golang.org/x/crypto/bcrypt"
)
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run pass.go <password>")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	fmt.Println(string(hash))
}
