package main

import (
	"fmt"
	"log"

	"github.com/tfogal/ptrace"
)

func main() {
	argv := []string{"./test-minimal"}
	inferior, err := ptrace.Exec(argv[0], argv)

	if err != nil {
		log.Fatalln(err)
	}

	defer inferior.Close()

	fmt.Println(inferior)
}
