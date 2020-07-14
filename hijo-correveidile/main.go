package main

import (
    "C"
    "fmt"
    "os"
    "log"
    "crypto/md5"
    "io"
    "runtime"
    "syscall"

    sec "github.com/seccomp/libseccomp-golang"
)


const (
    proctooled = "proctooled"
)

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    if os.Args[0] == proctooled {
        log.Println("Prepare to be amazed!")
        proc, err := os.StartProcess(os.Args[1], os.Args[1:], &os.ProcAttr{
            Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
            Sys: &syscall.SysProcAttr{
                // Setsid: true,
                Setpgid: true,
                Pgid: 0,
            },
        })
        if err != nil {
            log.Fatalln(err)
        }

        _, err = proc.Wait()
        if err != nil {
            log.Fatalln(err)
        }
    } else {
        runtime.LockOSThread()
        log.Printf("%+v\n", os.Args)
        proctooled, err := os.StartProcess(
            os.Args[0],
            append([]string{proctooled}, os.Args[1:]...),
            &os.ProcAttr{
                Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
                Sys: &syscall.SysProcAttr{
                    Ptrace: true,
                },
                Env: []string{"GOGC=off"},
            },
        )
        if err != nil {
            log.Fatalln(err)
        }

        _, err = proctooled.Wait()
        if err != nil {
            log.Fatalln(err)
        }

        pgid, err := syscall.Getpgid(proctooled.Pid)
        if err != nil {
            log.Fatalln(err)
        }

        // https://medium.com/golangspec/making-debugger-in-golang-part-ii-d2b8eb2f19e0
        err = syscall.PtraceSetOptions(
            proctooled.Pid,
            syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK|syscall.PTRACE_O_TRACEEXEC,
        )
        if err != nil {
            log.Fatalln(err)
        }

        err = syscall.PtraceAttach(proctooled.Pid)
        if err != syscall.EPERM {
            log.Fatalln(err)
        }

        err = syscall.PtraceCont(proctooled.Pid, 0)
        if err != nil {
            log.Fatalln(err)
        }

        log.Println("Corre Sara Connor")

        regs_of := make(map[int]*syscall.PtraceRegs)

        c := make(chan int)

        hashFileAndContinue := func(path string, pid int) {
            hash, err := hashFile(path)
            if err != nil {
                log.Fatalln(err)
            }
            log.Printf("pid: %d, path: %q, hash: %q\n", pid, path, hash)
            // TODO: not getting through
            err = syscall.Kill(proctooled.Pid, syscall.SIGUSR1)
            if err != nil {
                log.Fatalln(err)
            }
            // proctooled.Signal(syscall.SIGUSR10)
            c<-pid
            log.Println("Reported to channel")
        }

        for {
            wstatus := syscall.WaitStatus(0)
            pid, err := syscall.Wait4(-1, &wstatus, syscall.WALL, nil)
            if err != nil {
                log.Fatalln(err)
            }

            if wstatus.Exited() {
                log.Printf("I regret to inform you that your son %d died.  Moving on...\n", pid)
                continue
            }

            traceePgid, err := syscall.Getpgid(pid)
            if err != nil {
                log.Fatalln(err)
            }

            log.Printf("Awaken by pid: %d with pgid=%d (proctooled==%d pgid=%d)\n", pid, traceePgid, proctooled.Pid, pgid)

            if (pgid == traceePgid) {
                log.Println("Awakened by proctooled or one of its threads")
                // TODO: ensure that the sender of the signal is one of our goroutines (sender shares TGL with us)
                if (wstatus.StopSignal() == syscall.SIGUSR1) {
                    log.Println("Trying to read from channel n.5")
                    FOR:
                    for {
                        select {
                        case traceePid := <-c:
                            log.Println("Read pid from channel")
                            err = syscall.PtraceSyscall(traceePid, 0)
                            if err != nil {
                                log.Fatalln(err)
                            }
                        default:
                            log.Println("Channel depleted")
                            break FOR
                        }
                    }
                }

                err = syscall.PtraceCont(pid, int(wstatus.StopSignal()))
                if err != nil {
                    log.Fatalln(err)
                }
                continue
            }

            log.Println("Nietecito!")

            if wstatus.StopSignal() == syscall.SIGTRAP && wstatus.TrapCause() == 0 {
                regs := &syscall.PtraceRegs{}
                var direction string
                val, ok := regs_of[pid]
                if !ok {
                    direction = "user -> kernel"
                    err = syscall.PtraceGetRegs(pid, regs)
                    if err != nil {
                        log.Fatalln(err)
                    }
                    regs_of[pid] = regs
                    switch syscall_number := regs.Orig_rax; syscall_number {
                    case syscall.SYS_EXECVE:
                        path, err := readString(pid, uintptr(regs.Rdi))
                        if err != nil {
                            log.Println(err)
                        } else {
                            go hashFileAndContinue(path, pid)
                            log.Printf("execve(%q) path being hashed\n", path)
                            continue
                        }
                    }
                } else {
                    direction = "user <- kernel"
                    regs = val
                    delete(regs_of, pid)
                    switch syscall_number := regs.Orig_rax; syscall_number {
                    case syscall.SYS_OPENAT:
                        if regs.R10&syscall.O_RDWR != 0 {

                        } else if regs.R10&syscall.O_WRONLY != 0 {

                        } else { // O_RDONLY
                            if int64(regs.Rax) != -1 {
                                // TODO: what happens if child or grandchild is running in a chroot? or docker?
                                // the recovered path might not make sense to the tracer
                                // idea: /proc/pid/fd points to the actual file, no matter what
                                // idea: see if there is a syscall to retrieve this information, check how lsof does it

                                // TODO: do a PEEK via PTRACE to do a word-by-word read of what is pointed by regs.Rdi

                                // TODO: check line 17.  We have to better understand if this is a hard requisite or not
                                // log.Printf("hashea, hashea %q\n", C.GoString((*C.char)(unsafe.Pointer(&regs.Rdi))))

                                // TODO: this is going to call ptrace 4096%sizeOfWord times because it won't stop on nulls
                                // we can improve on this by building a function that is aware of the data copied
                                path, err := readString(pid, uintptr(regs.Rsi))
                                if err != nil {
                                    log.Fatalln(err)
                                }
                                go hashFileAndContinue(path, pid)
                                log.Printf("openat(%q, O_RDONLY) path being hashed\n", path)
                                continue
                            }
                        }
                    }
                }
                log.Printf(
                    "direction: %s, pid: %d, syscall: %q\n",
                    direction,
                    pid,
                    getSyscallName(regs.Orig_rax),
                )
            }
            if !wstatus.Exited() {
                err = syscall.PtraceSyscall(pid, 0)
                if err != nil {
                    log.Fatalln("le_err", err)
                }
            }
        }

    }
}

func readString(pid int, addr uintptr) (string, error) {
    data := make([]byte, 4096)
    bytes_copied, _ := syscall.PtracePeekData(pid, addr, data)
    if bytes_copied == 0 {
        return "", fmt.Errorf("0-byte string returned")
    }
    str := C.GoString((*C.char)(C.CBytes(data)))
    return str, nil
}

func hashFile(filename string) (string, error) {
    f, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer f.Close()

    h := md5.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", err
    }

    return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func getSyscallName(syscall_ID uint64) string {
	name, _ := sec.ScmpSyscall(syscall_ID).GetName()
	return name
}
