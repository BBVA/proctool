package main

import (
	"log"
	"os"
	"syscall"
	"runtime"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	argv := []string{"./test-minimal"}

	runtime.LockOSThread()
	proc, err := os.StartProcess(argv[0], argv, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Ptrace:    true,
		},
	})
	if err != nil { log.Fatalln(err) }

	state, err := proc.Wait()
	if err != nil { log.Fatalln(err) }
	pgid, err := syscall.Getpgid(proc.Pid)

	// https://medium.com/golangspec/making-debugger-in-golang-part-ii-d2b8eb2f19e0
	err = syscall.PtraceSetOptions(proc.Pid, syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK)

	err = syscall.PtraceAttach(proc.Pid)

	if err != syscall.EPERM {
		log.Fatalln(err)
	}

	log.Printf("%+v\n", proc)
	log.Printf("%+v\n", state)
	log.Printf("%+v\n", err)

	err = syscall.PtraceSyscall(proc.Pid, 0)
	if err != nil { log.Fatalln(err) }

	for {
		status := syscall.WaitStatus(0)
		pid, err := syscall.Wait4(-1*pgid, &status, syscall.WALL, nil)
		if err != nil { log.Fatalln(err) }

		if pid == proc.Pid && status.Exited() {
			log.Printf("parent pid %d exited\n", pid)
			continue
		}
		if !status.Exited() {
			regs := &syscall.PtraceRegs{}
			err = syscall.PtraceGetRegs(pid, regs)
			if err != nil { log.Fatalln(err) }

			syscall_number := regs.Orig_rax

			log.Printf("pid: %d, syscall_number: %+v\n", pid, syscall_number)
			err = syscall.PtraceSyscall(pid, 0)
			if err != nil { log.Fatalln("le_err", err) }
		}
	}
}
