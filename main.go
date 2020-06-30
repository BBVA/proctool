package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"runtime"

	"github.com/hjr265/ptrace.go/ptrace"
)

func main() {
	argv := []string{"./test-minimal"}

	runtime.LockOSThread()
	proc, err := os.StartProcess(argv[0], argv, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Ptrace:    true,
			Pdeathsig: syscall.SIGCHLD,
		},
	})
	if err != nil {
		log.Fatalln(err)
	}

	state, err := proc.Wait()
	if err != nil {
		log.Fatalln(err)
	}

	tracer, err := ptrace.Attach(proc)

	fmt.Printf("%+v\n%+v\n%+v\n%+v\n", proc, state, tracer, err)


	for {
		syscall_number, err := tracer.Syscall(0)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("syscall_number: %+v\n", syscall_number)
	}
}
