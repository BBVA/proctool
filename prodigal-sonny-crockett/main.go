package main

import (
    "log"
    "os"
    "runtime"
    "sync"
    "syscall"
)

const (
    // http://www.catb.org/jargon/html/B/biff.html
    // TODO: explain what and why
    BIFF_PROCESS = "[ProcTool Biff]"

    CHANNEL_READY = syscall.SIGUSR1

    IS_BIFF = (1 << 0)
    IS_SYSCALL = (1 << 1)
    IS_SIGNAL = (1 << 2)
    IS_EXIT = (1 << 3)

    STOPCAUSE_IGNORABLE = 0
    STOPCAUSE_SURVEILLED_SYSCALL = IS_SYSCALL
    STOPCAUSE_SURVEILLED_SIGNAL = IS_SIGNAL
    STOPCAUSE_SURVEILLED_EXIT = IS_EXIT
    STOPCAUSE_BIFF_SYSCALL = IS_BIFF|IS_SYSCALL
    STOPCAUSE_BIFF_SIGNAL = IS_BIFF|IS_SIGNAL
    STOPCAUSE_BIFF_EXIT = IS_BIFF|IS_EXIT

    SYSCALL_STOP_POINT_OPENAT_RETURN
    SYSCALL_STOP_POINT_EXECVE_CALL
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
    alteredFiles := make([string]*sync.RWMutex) // addressing by path

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
            switch syscallStopPoint := decodeSyscallStopPoint; syscallStopPoint {
            case SYSCALL_STOP_POINT_EXECVE_CALL:
                path := getOpenPath()
                go hashFileAndContinue(traceePid, fd, path) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
            case SYSCALL_STOP_POINT_OPENAT_RETURN:
                if syscall_was_successful() {
                    path := getOpenPath()
                    switch mode := getOpenMode(); mode {
                    case MODE_O_RDONLY:
                        go hashFile(traceePid, fd, path) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
                        // delete(alteredFiles, path) // Ensure path is removed from table (might not be present)
                        syscall.PtraceSyscall(traceePid, 0)
                    case MODE_O_RDWR:
                        go hashFileAndContinue(traceePid, fd, path) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
                        alteredFiles[path] = true
                    case MODE_O_WRONLY: // Nota del Ruso: sólo importan las lecturas; WR al cierre (0x1623498761923487162938764912837649128374691)
                        _, isAltered := alteredFiles[path]
                        alteredFiles[path] = true // This update is strictly required when value is undefined, but setting it unconditionally for simplicity
                        if isAltered {
                            go hashFileAndContinue(pid, fd, path) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
                        } else {
                            syscall.PtraceSyscall(pid, 0)
                        }
                    }
                } else {
                    syscall.PtraceSyscall(pid, 0)
                }
            default:
                syscall.PtraceSyscall(pid, 0)
            }

        default:
            log.Fatalf("Shouldn't happen")
        }
    }
}
