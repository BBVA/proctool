package main

import (
    "C"
    "crypto/md5"
    "fmt"
    "io"
    "log"
    "os"
    "runtime"
    "sync"
    "syscall"
)

const (
    // http://www.catb.org/jargon/html/B/biff.html
    // TODO: explain what and why
    // TODO: rename constants to follow Go's conventions
    BIFF_PROCESS = "[ProcTool Biff]"

    CHANNEL_READY = syscall.SIGUSR1

    IS_BIFF    = 1 << iota
    IS_SYSCALL
    IS_SIGNAL
    IS_EXIT

    STOPCAUSE_IGNORABLE          = 0
    STOPCAUSE_SURVEILLED_SYSCALL = IS_SYSCALL
    STOPCAUSE_SURVEILLED_SIGNAL  = IS_SIGNAL
    STOPCAUSE_SURVEILLED_EXIT    = IS_EXIT
    STOPCAUSE_BIFF_SYSCALL       = IS_BIFF | IS_SYSCALL
    STOPCAUSE_BIFF_SIGNAL        = IS_BIFF | IS_SIGNAL
    STOPCAUSE_BIFF_EXIT          = IS_BIFF | IS_EXIT

    SYSCALL_STOP_POINT_UNMONITORED = iota
    SYSCALL_STOP_POINT_OPENAT_RETURN
    SYSCALL_STOP_POINT_EXECVE_CALL

    MODE_O_RDONLY = iota
    MODE_O_RDWR
    MODE_O_WRONLY
)

func main() {
    setupLogger()
    if isTracer() {
        os.Exit(trace())
    } else {
        // I am Biff
        os.Exit(spawnSurveilled())
    }
}

func setupLogger() {
    // TODO: check the environment for var: TBD that signifies where to send the output (path to file)
    // TODO: config log to produce line numbers upon log.Print*
    // TODO: we need a logger for the special occasions (when surveilled cannot be
    // spawned, or traced, or whatever).   When abort is the only way forward.
    // We'll dump info to stderr, then.
}

func isTracer() bool {
    return os.Args[0] != BIFF_PROCESS
}

// spawnSurveilled spawns the process to be traced
// and returns the exit code of the spawned command
// without tainting stdout nor stderr
func spawnSurveilled() (exitCode int) {
    proc, err := os.StartProcess(os.Args[1], os.Args[1:], &os.ProcAttr{
        Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
        Sys: &syscall.SysProcAttr{
            Setpgid: true,
            Pgid: 0, // Use a new pgid to assist the calling process isolate the events of the surveilled
        },
    })
    if err != nil {
        // TODO: mimic bash -c; to stderr: <error>, and return 127, 126, who knows...
        // https://tldp.org/LDP/abs/html/exitcodes.html
        // This is a dark and dense forest.  Prepare for the ride.  For now,
        exitCode = 127
        return
    }

    pstate, err := proc.Wait()
    if err != nil {
        log.Printf("proctool: %+v", err)
        return 1
    }

    exitCode = pstate.ExitCode()
    return
}

func startBiff() (pid, pgid int, err error) {
    biff, err := os.StartProcess(
        os.Args[0],
        append([]string{BIFF_PROCESS}, os.Args[1:]...),
        &os.ProcAttr{
            Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
            Sys: &syscall.SysProcAttr{
                Ptrace: true,
            },
        },
    )
    if err != nil {
        return
    }
    pid = biff.Pid

    _, err = biff.Wait()
    if err != nil {
        return
    }

    pgid, err = syscall.Getpgid(biff.Pid)
    return
}

func traceBiff(pid int) error {
    // https://medium.com/golangspec/making-debugger-in-golang-part-ii-d2b8eb2f19e0
    err := syscall.PtraceSetOptions(
        pid,
        syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK|syscall.PTRACE_O_TRACEEXEC,
    )
    if err != nil {
        return err
    }

    return syscall.PtraceCont(pid, 0)
}

func decodeStopCause(wstatus syscall.WaitStatus, traceePid, biffPgid int) (stopCause int) {
    traceePgid, err := syscall.Getpgid(traceePid)
    if err != nil {
        // TODO: log event to file (tracee was possibly SIGKILLed)
        stopCause = STOPCAUSE_IGNORABLE
        return
    }

    if traceePgid == biffPgid {
        stopCause |= IS_BIFF
    }

    if wstatus.Exited() {
        stopCause |= IS_EXIT
    } else if wstatus.StopSignal() == syscall.SIGTRAP && wstatus.TrapCause() == 0 {
        stopCause |= IS_SYSCALL
    } else {
        stopCause |= IS_SIGNAL
    }

    return
}

func isAsyncTaskFinishedSignal(biffPgid int, wstatus syscall.WaitStatus) bool {
    // TODO: check that the sender.Pgid matches biffPgid
    return wstatus.StopSignal() == CHANNEL_READY
}

type safeBool struct {
    Value bool
    m *sync.Mutex
}

func (f *safeBool) Lock() {
    f.m.Lock()
}

func (f *safeBool) SetAndUnlock(v bool) {
    f.Value = v
    f.m.Unlock()
}

func decodeSyscallStopPoint(regs syscall.PtraceRegs, isReturning bool) int {

    // NOTE: ptrace stop-enter-syscall and stop-exit-syscall cannot be
    // distinguised by the contents of the registers.
    // RTFM!
    if syscall_number := regs.Orig_rax; syscall_number == syscall.SYS_EXECVE && !isReturning { 
        return SYSCALL_STOP_POINT_EXECVE_CALL
    } else if syscall_number == syscall.SYS_OPENAT && isReturning {
        return SYSCALL_STOP_POINT_OPENAT_RETURN
    } else {
        return SYSCALL_STOP_POINT_UNMONITORED
    }
}

func getOpenAtPath(pid int, regs syscall.PtraceRegs) (string, error) {
    path, err := readString(pid, uintptr(regs.Rsi))
    if err != nil {
        return "", err
    }
    return path, nil
}

func getExecvePath(pid int, regs syscall.PtraceRegs) (string, error) {
    path, err := readString(pid, uintptr(regs.Rdi))
    if err != nil {
        return "", err
    }
    return path, nil
}

func hashExecAndContinue(pid int, path string) {
    // TODO: revisit this function's name
}

func isOpenAtOk(regs syscall.PtraceRegs) bool {
    return int64(regs.Rax) > -1
}

func getOpenAtMode(regs syscall.PtraceRegs) int {
    if regs.R10&syscall.O_RDWR != 0 {
        return MODE_O_RDWR
    } else if regs.R10&syscall.O_WRONLY != 0 {
        return MODE_O_WRONLY
    } else { // O_RDONLY
        return MODE_O_RDONLY
    }
}

func getOpenAtFd(regs syscall.PtraceRegs) int {
    return int(regs.Rax)
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

func hashFile(pid, fd int, filename string) {
    f, err := os.Open(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
    if err != nil {
        // TODO: log open failed
        return
    }
    defer f.Close()

    h := md5.New()
    if _, err := io.Copy(h, f); err != nil {
        // TODO: log hash failed
        return
    }

    log.Printf("%s: %x\n", filename, h.Sum(nil))
}

func hashFileAndContinue(biffPid, traceePid, fd int, filename string, stoppedSurveilledPid chan int) {
    hashFile(traceePid, fd, filename)

    err := syscall.Kill(biffPid, CHANNEL_READY)
    if err != nil {
        // TODO: use proper logger
        log.Fatalln(err)
    }
    stoppedSurveilledPid<-traceePid
}

func trace() int {
    runtime.LockOSThread()

    biffPid, biffPgid, err := startBiff()
    if err != nil {
        log.Fatalln(err) // TODO: use stderr logger
    }

    err = traceBiff(biffPid)
    if err != nil {
        log.Fatalln(err) // TODO: use stderr logger
    }

    stoppedSurveilledPid := make(chan int)
    // TODO: use sync.Map to ensure safe concurrent access

    var alteredFiles sync.Map // addressing by path [string]*safeBool
    returningFromSyscall := make(map[int]bool)

    for {
        wstatus := syscall.WaitStatus(0)
        traceePid, err := syscall.Wait4(-1, &wstatus, syscall.WALL, nil)
        if err != nil {
            log.Fatalln(err) // TODO: use file logger
        }

        switch stopCause := decodeStopCause(wstatus, traceePid, biffPgid); stopCause {
        case STOPCAUSE_BIFF_EXIT:
            return wstatus.ExitStatus()
        case STOPCAUSE_BIFF_SIGNAL:
            if isAsyncTaskFinishedSignal(biffPgid, wstatus) {
                syscall.PtraceSyscall(<-stoppedSurveilledPid, 0)
                syscall.PtraceCont(traceePid, 0)
            } else {
               syscall.PtraceCont(traceePid, int(wstatus.StopSignal()))
            }
        case STOPCAUSE_BIFF_SYSCALL:
            syscall.PtraceCont(traceePid, 0)

        case STOPCAUSE_SURVEILLED_EXIT:
            // TODO: it's reckoning day! hash any files opened by the deceased,
            // which might have not percolated via ptrace() because reasons
            // (and the kernel closed on its behalf)

            // TODO: this hash should only happen if this process was the last
            // writer standing (either, O_RDWR, or O_WRONLY)

        case STOPCAUSE_SURVEILLED_SIGNAL:
            syscall.PtraceSyscall(traceePid, int(wstatus.StopSignal()))

        case STOPCAUSE_SURVEILLED_SYSCALL:
            // TODO: encapsulate this in a struct w/ decodeSyscallStopPoint as a method?
            isReturning := returningFromSyscall[traceePid]
            returningFromSyscall[traceePid] = !isReturning

            regs := &syscall.PtraceRegs{}
            err = syscall.PtraceGetRegs(traceePid, regs)
            if err != nil {
                // TODO: log process is dead
                continue
            }

            switch syscallStopPoint := decodeSyscallStopPoint(*regs, isReturning); syscallStopPoint {
            case SYSCALL_STOP_POINT_EXECVE_CALL:
                path, err := getExecvePath(traceePid, *regs)
                if err != nil {
                    // TODO: log *path is not pointing to a string
                    syscall.PtraceSyscall(traceePid, 0)
                } else {
                    // TODO: there is no such thing as an `fd` here
                    go hashExecAndContinue(traceePid, path) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
                }
            case SYSCALL_STOP_POINT_OPENAT_RETURN:
                if isOpenAtOk(*regs) {
                    path, err := getOpenAtPath(traceePid, *regs)
                    if err != nil {
                        // TODO: log *path is not pointing to a string
                        syscall.PtraceSyscall(traceePid, 0)
                    } else {
                        fd := getOpenAtFd(*regs)
                        switch mode := getOpenAtMode(*regs); mode {
                        case MODE_O_RDONLY:
                            // Dead or alive, you're coming with me
                            func () {
                                tmp, _ := alteredFiles.LoadOrStore(path, &safeBool{})
                                flag := tmp.(*safeBool)
                                flag.Lock()
                                defer flag.SetAndUnlock(false)
                                go hashFile(traceePid, fd, path) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
                                err := syscall.PtraceSyscall(traceePid, 0)
                                if err != nil {
                                    // TODO: log process is dead
                                }
                            }()
                        case MODE_O_RDWR:
                            go func () {
                                tmp, _ := alteredFiles.LoadOrStore(path, &safeBool{})
                                flag := tmp.(*safeBool)
                                flag.Lock()
                                defer flag.SetAndUnlock(true)
                                hashFileAndContinue(biffPid, traceePid, fd, path, stoppedSurveilledPid) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
                            }()
                        case MODE_O_WRONLY: // Nota del Ruso: sólo importan las lecturas; WR al cierre (0x1623498761923487162938764912837649128374691)
                            func () {
                                tmp, _ := alteredFiles.LoadOrStore(path, &safeBool{})
                                flag := tmp.(*safeBool)
                                flag.Lock()
                                defer flag.SetAndUnlock(true)
                                err := syscall.PtraceSyscall(traceePid, 0)
                                if err != nil {
                                    // TODO: log process is dead
                                }
                            }()
                        }
                    }
                } else {
                    syscall.PtraceSyscall(traceePid, 0)
                }
            default:
                syscall.PtraceSyscall(traceePid, 0)
            }

        default:
            log.Fatalf("Shouldn't happen")
        }
    }
}
