package main

import (
)

const (
    FOREMAN_PROCESS = "[ProcTool Tracee]"
)

func main() {
    setup()
    if isTracer() {
        return trace()
    } else {
        // I am the foreman
        return spawnTracee()
    }
}

func setup() {
    // TODO (maybe): take care of backing up stdin, stdout, stderr ?
    setupLogger()
    setupFoo() // ...
}

func setupLogger() {
    // TODO: check the environment for var: TBD that signifies where to send the output (path to file)
    // TODO: config log to produce line numbers upon log.Print*
}


func isTracer() bool {
    return os.Args[0] != FOREMAN_PROCESS
}

func spawnTracee() (rc int) {

    // TODO: spawn a process ex os.Args[1:] 
    // TODO: ^^^^^ tweak the pgid or whatever
    // TODO: exit with the same return code as the spawned process (don't alter the expected behavior)
    // TODO: std* fds must be conserved (don't alter the expected behavior)

    rc = 0 // hopefully! :-)
}

func tracer() {
    // TODO: runtime.LockOSThread()

    // TODO: spawn a process named FOREMAN_PROCESS with ptrace: true, etc..., with os.Args[1:]

    // TODO: obtain the pgid, which will enable us to prune out noise (events that don't pertain the tracees proper)

    // TODO: the spawned process is stopped (à la ptrace); wait until ready

    // TODO: setup ptrace() options that enables us to track forks, clones, execs and transgender ops

    // TODO: restart the motherfucker (Continue forevah)

    // TODO: Le loop
    for {
        // TODO: instantiate wstatus
        // pid, wstatus = < wait until children cry (state change) >
        // defer register fetching until reason for awakening warrants it, so:

        // discuss the reason for the awakening


        switch stopCause := decodeStopCause(wstatus, pid, pgid); stopCause {
        case STOPCAUSE_FOREMAN_EXIT:
            return // TODO: foreman's exit status
        case STOPCAUSE_FOREMAN_SIGNAL:
            if isAsyncTaskFinishedSignal(...) {
                // TODO: syscall.PtraceSyscall(<-stoppedTraceePid)
                // TODO: ignoreSignal, by just calling syscall.PtraceCont(pid, 0)
            } else {
               syscall.PtraceCont(pid, TODO: signal)
            }
        case STOPCAUSE_FOREMAN_SYSCALL:
            syscall.PtraceCont(pid, 0)

        case STOPCAUSE_TRACEE_EXIT:
            // TODO: it's reckoning day! hash any files opened by the deceased, which might have not percolated via ptrace() because reasons (and the kernel closed on its behalf)
            // TODO: this hash should only happen if this process was the last writer standing (either, O_RDWR, or O_WRONLY)

        case STOPCAUSE_TRACEE_SIGNAL:
            syscall.PtraceSyscall(pid, TODO: signal)

        case STOPCAUSE_TRACEE_SYSCALL:
            switch syscallStopPoint := decodeSyscallStopPoint; syscallStopPoint {
            case SYSCALL_STOP_POINT_EXECVE_CALL:
                // TODO: extract path
                // asynchronously hash that path, leaving the tracee stopped (will be awakened when handling STOPCAUSE_FOREMAN_SIGNAL > isAsyncTaskFinishedSignal()
            case SYSCALL_STOP_POINT_OPENAT_CALL:
                // Ignored
            case SYSCALL_STOP_POINT_OPENAT_RETURN:
                if syscall_was_successful() {
                    switch mode := damElModePlis(); mode {
                        case MODE_O_RDONLY, MODE_O_RDWR:
                            go hashFileAndContinue(pid, fd, path) // process continuation will be handled by STOPCAUSE_FOREMAN_SIGNAL > isAsyncTaskFinishedSignal()

                        case MODE_O_WRONLY: // Nota del Ruso: sólo importan las lecturas; WR al cierre (0x1623498761923487162938764912837649128374691)
                    }
                }
            default:
                syscall.PtraceSyscall(pid, 0)
            }

        default:
            log.Fatalf("Shouldn't happen")
        }
    }
}
