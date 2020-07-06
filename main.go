package main

import (
	"C"
	"log"
	"os"
	"syscall"
	"runtime"
	"unsafe"
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

	regs_of := make(map[int]*syscall.PtraceRegs)

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
			var direction string
			val, ok := regs_of[pid]
			if !ok {
				direction = "user -> kernel"
				err = syscall.PtraceGetRegs(pid, regs)
				if err != nil { log.Fatalln(err) }
				regs_of[pid]=regs
			} else {
				direction = "user <- kernel"
				regs = val
				delete(regs_of, pid)
				switch syscall_number := regs.Orig_rax; syscall_number {
				case syscall.SYS_OPENAT:
					if regs.R10 & syscall.O_RDWR != 0 {

					} else if regs.R10 & syscall.O_WRONLY != 0 {

					} else { // O_RDONLY
						if int64(regs.Rax) != -1 {
							// TODO: what happens if child or grandchild is running in a chroot? or docker?
							// the recovered path might not make sense to the tracer
							// idea: /proc/pid/fd points to the actual file, no matter what
							// idea: see if there is a syscall to retrieve this information, check how lsof does it

							// TODO: do a PEEK via PTRACE to do a word-by-word read of what is pointed by regs.Rdi

							// TODO: check line 17.  We have to better understand if this is a hard requisite or not
							log.Printf("hashea, hashea %q\n", C.GoString((*C.char)(unsafe.Pointer(&regs.Rdi))))
						}
					}
				}
			}
			log.Printf("direction: %s, pid: %d, syscall_number: %+v\n", direction, pid, regs.Orig_rax)
			err = syscall.PtraceSyscall(pid, 0)
			if err != nil { log.Fatalln("le_err", err) }
		}
	}
}
