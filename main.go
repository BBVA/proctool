package main

// CAVEAT EMPTOR: The current design assumes that the surveilled process spawned by
// BIFF will wait for each and every descendant to die before dying himself.
// Otherwise, the descendants surviving the parent surveilled process won't be
// monitored after the fact.

// FIXME: No grandsons of the parent surveilled process are monitored
// FIXME: Some of the parent surveilled process go undetected, apparently

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

	"go.uber.org/zap" // https://github.com/uber-go/zap
)

const (
	// http://www.catb.org/jargon/html/B/biff.html
	// TODO: explain what and why
	// TODO: rename constants to follow Go's conventions
	BIFF_PROCESS = "[ProcTool Biff]"

	CHANNEL_READY = syscall.SIGUSR1

	IS_BIFF = 1 << iota
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
	// XXX: Can we initialize the logger here? We have to ensure syncing
	// with a defer (can we even do that with os.Exit on main?)
	//
	// setupLogger()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	os.Exit(trace())
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

func startBiff() (pid, pgid int, err error) {
	biff, err := os.StartProcess(
		"bin/biff", // NOTE: MVP has a hardcoded path on Biff
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

	return syscall.PtraceSyscall(pid, 0)
}

func decodeStopCause(wstatus syscall.WaitStatus, traceePid, biffPid int) (stopCause int) {
	if traceePid == biffPid {
		stopCause |= IS_BIFF
	}

	if wstatus.Exited() {
		stopCause |= IS_EXIT
	} else if wstatus.StopSignal() == syscall.SIGTRAP {
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
	m     sync.Mutex
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

func sendContinue(biffPid, traceePid int, stoppedSurveilledPid chan int) {
	err := syscall.Kill(biffPid, CHANNEL_READY)
	if err != nil {
		zap.L().Error("Cannot signal biff about available message", zap.Error(err))
	}
	stoppedSurveilledPid <- traceePid
}

func hashFileAndContinue(biffPid, traceePid, fd int, path string, stoppedSurveilledPid chan int) {
	defer sendContinue(biffPid, traceePid, stoppedSurveilledPid)

	if hash, err := hashFile(fmt.Sprintf("/proc/%d/fd/%d", traceePid, fd)); err != nil {
		zap.L().Error("Cannot hash file via fd", zap.Int("pid", traceePid), zap.Int("fd", fd), zap.String("path", path), zap.Error(err))
	} else {
		zap.L().Info("Hashed file", zap.String("path", path), zap.String("hash", hash))
	}

	return
}

func hashExecAndContinue(biffPid, traceePid int, path string, stoppedSurveilledPid chan int) {
	defer sendContinue(biffPid, traceePid, stoppedSurveilledPid)
	if hash, err := hashFile(path); err != nil {
		zap.L().Error("Cannot hash file via path", zap.String("path", path), zap.Error(err))
	} else {
		zap.L().Info("Hashed file", zap.String("path", path), zap.String("hash", hash))
	}

	return
}

func trace() (exitStatus int) {
	runtime.LockOSThread()

	zap.L().Info("Starting biff process")
	biffPid, biffPgid, err := startBiff()
	if err != nil {
		zap.L().Fatal("Cannot start biff process", zap.Error(err))
	}

	err = traceBiff(biffPid)
	if err != nil {
		zap.L().Fatal("Cannot trace biff process", zap.Error(err))
	}

	var alteredFiles sync.Map // addressing by path [string]*safeBool
	var pendingHashes sync.WaitGroup
	stoppedSurveilledPid := make(chan int)
	returningFromSyscall := make(map[int]bool)
	traceStep := 0

	defer pendingHashes.Wait()
	defer alteredFiles.Range(
		func(key, value interface{}) bool {
			pendingHashes.Add(1)
			go func() {
				defer pendingHashes.Done()

				path := key.(string)
				wasModified := value.(*safeBool)

				wasModified.Lock()
				defer wasModified.SetAndUnlock(false)

				// Already hashed, skipping
				if !wasModified.Value {
					return
				}

				if hash, err := hashFile(path); err != nil {
					zap.L().Error(
						"A pending hash cannot be performed.  Maybe the file was deleted?",
						zap.String("path", path),
						zap.Bool("wasModified", wasModified.Value),
					)
				} else {
					zap.L().Info(
						"A pending hash was performed after all processes finished.",
						zap.String("path", path),
						zap.Bool("wasModified", wasModified.Value),
						zap.String("hash", hash))
				}
			}()
			return true
		})

	for {
		traceStep++
		wstatus := syscall.WaitStatus(0)
		traceePid, err := syscall.Wait4(-1, &wstatus, syscall.WALL, nil)
		if err != nil {
			zap.L().Info("There are no more children to wait for", zap.Error(err), zap.Int("traceStep", traceStep))
			// XXX: This will happend once all children finish
			return
		}

		switch stopCause := decodeStopCause(wstatus, traceePid, biffPid); stopCause {
		case STOPCAUSE_BIFF_EXIT:
			exitStatus = wstatus.ExitStatus()
			zap.L().Info(
				"Biff process exited",
				zap.Int("traceePid", traceePid),
				zap.String("stopCause", "STOPCAUSE_BIFF_EXIT"),
				zap.Int("traceStep", traceStep),
				zap.Int("exitStatus", exitStatus),
			)
		case STOPCAUSE_BIFF_SIGNAL:
			if isAsyncTaskFinishedSignal(biffPgid, wstatus) {
				surveilledToBeContinued := <-stoppedSurveilledPid
				zap.L().Info(
					"Biff process received a signal from an async task allowing a surveilled to continue",
					zap.Int("traceePid", traceePid),
					zap.String("stopCause", "STOPCAUSE_BIFF_SIGNAL"),
					zap.Int("traceStep", traceStep),
					zap.Int("surveilledToBeContinued", surveilledToBeContinued))
				syscall.PtraceSyscall(surveilledToBeContinued, 0)
				syscall.PtraceSyscall(traceePid, 0)
				// TODO: Capture errors
			} else {
				zap.L().Info(
					"Biff process received an unknown signal!",
					zap.Int("traceePid", traceePid),
					zap.String("stopCause", "STOPCAUSE_BIFF_SIGNAL"),
					zap.Int("traceStep", traceStep),
					zap.Int("stopSignal", int(wstatus.StopSignal())),
				)
				syscall.PtraceSyscall(traceePid, int(wstatus.StopSignal()))
			}
		case STOPCAUSE_BIFF_SYSCALL:
			zap.L().Info(
				"Biff process stop calling or returning from syscall",
				zap.Int("traceePid", traceePid),
				zap.String("stopCause", "STOPCAUSE_BIFF_SYSCALL"),
				zap.Int("traceStep", traceStep),
			)
			syscall.PtraceSyscall(traceePid, 0)

		case STOPCAUSE_SURVEILLED_EXIT:
			zap.L().Info("Surveiled process exited", zap.Int("traceePid", traceePid), zap.String("stopCause", "STOPCAUSE_SURVEILLED_EXIT"), zap.Int("traceStep", traceStep))
			// TODO: it's reckoning day! hash any files opened by the deceased,
			// which might have not percolated via ptrace() because reasons
			// (and the kernel closed on its behalf)

			// TODO: this hash should only happen if this process was the last
			// writer standing (either, O_RDWR, or O_WRONLY)

		case STOPCAUSE_SURVEILLED_SIGNAL:
			zap.L().Info("Surveiled process received a signal", zap.Int("traceePid", traceePid), zap.String("stopCause", "STOPCAUSE_SURVEILLED_SIGNAL"), zap.Int("traceStep", traceStep))
			syscall.PtraceSyscall(traceePid, int(wstatus.StopSignal()))

		case STOPCAUSE_SURVEILLED_SYSCALL:
			// TODO: encapsulate this in a struct w/ decodeSyscallStopPoint as a method?
			isReturning := returningFromSyscall[traceePid]
			returningFromSyscall[traceePid] = !isReturning

			regs := &syscall.PtraceRegs{}
			err = syscall.PtraceGetRegs(traceePid, regs)
			if err != nil {
				zap.L().Error("Error reading registers of a surveiled process when tracing a syscall. Maybe the process was killed?", zap.Int("traceePid", traceePid), zap.Int("traceStep", traceStep), zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"))
				continue
			}

			switch syscallStopPoint := decodeSyscallStopPoint(*regs, isReturning); syscallStopPoint {
			case SYSCALL_STOP_POINT_EXECVE_CALL:
				path, err := getExecvePath(traceePid, *regs)
				if err != nil {
					zap.L().Error(
						"Error analyzing execve() syscall. path was not pointing to a proper string",
						zap.Int("traceePid", traceePid),
						zap.Error(err),
						zap.Int("traceStep", traceStep),
						zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
						zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_EXECVE_CALL"))
					syscall.PtraceSyscall(traceePid, 0)
				} else {
					zap.L().Info(
						"A execve() was intercepted and the pointed path found.  Hashing file before allowing the process to continue",
						zap.Int("traceePid", traceePid),
						zap.Int("traceStep", traceStep),
						zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
						zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_EXECVE_CALL"))
					pendingHashes.Add(1)
					go func() {
						defer pendingHashes.Done()
						hashExecAndContinue(biffPid, traceePid, path, stoppedSurveilledPid) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
					}()
				}
			case SYSCALL_STOP_POINT_OPENAT_RETURN:
				if isOpenAtOk(*regs) {
					path, err := getOpenAtPath(traceePid, *regs)
					if err != nil {
						zap.L().Error(
							"Kernel reported that the file was open correctly but we can't read the path string",
							zap.Error(err),
							zap.Int("traceePid", traceePid),
							zap.Int("traceStep", traceStep),
							zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"),
							zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"))
						syscall.PtraceSyscall(traceePid, 0)
					} else {
						fd := getOpenAtFd(*regs)
						switch mode := getOpenAtMode(*regs); mode {
						case MODE_O_RDONLY:
							zap.L().Info(
								"Surveilled is about to open a file in RDONLY mode.  Hashing in background and allowing it to continue.",
								zap.Int("traceePid", traceePid),
								zap.Int("traceStep", traceStep),
								zap.Int("fd", fd),
								zap.String("path", path),
								zap.String("mode", "MODE_O_RDONLY"),
								zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
								zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"))
							// Dead or alive, you're coming with me
							func() {
								tmp, _ := alteredFiles.LoadOrStore(path, &safeBool{})
								flag := tmp.(*safeBool)
								flag.Lock()
								defer flag.SetAndUnlock(false)
								pendingHashes.Add(1)
								go func() {
									defer pendingHashes.Done()
									if hash, err := hashFile(fmt.Sprintf("/proc/%d/fd/%d", traceePid, fd)); err != nil {
										zap.L().Error(
											"Cannot hash file via fd",
											zap.Error(err),
											zap.Int("traceePid", traceePid),
											zap.Int("traceStep", traceStep),
											zap.String("path", path),
											zap.String("mode", "MODE_O_RDONLY"),
											zap.Int("fd", fd),
											zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
											zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"))
									} else {
										zap.L().Info(
											"Successful file hash",
											zap.String("path", path),
											zap.String("hash", hash),
											zap.String("mode", "MODE_O_RDONLY"),
											zap.Int("traceePid", traceePid),
											zap.Int("traceStep", traceStep),
											zap.Int("fd", fd),
											zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
											zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"))
									}
									return
								}()
								err := syscall.PtraceSyscall(traceePid, 0)
								if err != nil {
									zap.L().Error(
										"Error allowing surveiled to continue after stopping it in an openat call.  Maybe the process was killed?",
										zap.Error(err),
										zap.Int("traceePid", traceePid),
										zap.Int("traceStep", traceStep),
										zap.String("path", path),
										zap.String("mode", "MODE_O_RDONLY"),
										zap.Int("fd", fd),
										zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
										zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"))
								}
							}()
						case MODE_O_RDWR:
							zap.L().Info(
								"Surveilled is about to open a file in RDWR mode.  Stopping it until the hash is done.",
								zap.Int("traceePid", traceePid),
								zap.Int("traceStep", traceStep),
								zap.Int("fd", fd),
								zap.String("path", path),
								zap.String("mode", "MODE_O_RDWR"),
								zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
								zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"))
							pendingHashes.Add(1)
							go func() {
								defer pendingHashes.Done()
								tmp, _ := alteredFiles.LoadOrStore(path, &safeBool{})
								flag := tmp.(*safeBool)
								flag.Lock()
								defer flag.SetAndUnlock(true)
								hashFileAndContinue(biffPid, traceePid, fd, path, stoppedSurveilledPid) // process continuation will be handled by STOPCAUSE_BIFF_SIGNAL > isAsyncTaskFinishedSignal()
							}()
						case MODE_O_WRONLY: // Nota del Ruso: sólo importan las lecturas; WR al cierre (0x1623498761923487162938764912837649128374691)
							zap.L().Info(
								"Surveilled is about to open a file in WRONLY mode.  We will mark this file as modified; it will be hashed when another process tries to open it for reading or when everyone dies.",
								zap.Int("traceePid", traceePid),
								zap.Int("traceStep", traceStep),
								zap.Int("fd", fd),
								zap.String("path", path),
								zap.String("mode", "MODE_O_WRONLY"),
								zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
								zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"))
							func() {
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
					zap.L().Info(
						"The process tried to open a file but the kernel returned an error",
						zap.Int("traceePid", traceePid),
						zap.Int("traceStep", traceStep),
						zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
						zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_OPENAT_RETURN"),
					)
					syscall.PtraceSyscall(traceePid, 0)
				}
			case SYSCALL_STOP_POINT_UNMONITORED:
				zap.L().Info(
					"Analyzing SYSCALL_STOP_POINT_UNMONITORED",
					zap.Int("traceePid", traceePid),
					zap.Int("traceStep", traceStep),
					zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
					zap.String("syscallStopPoint", "SYSCALL_STOP_POINT_UNMONITORED"),
					zap.Int("Orig_rax", int(regs.Orig_rax)),
					zap.Int("biffPid", biffPid),
				)
				syscall.PtraceSyscall(traceePid, 0)
			default:
				zap.L().Fatal(
					"Unmanaged SYSCALL_STOP_POINT",
					zap.Int("traceePid", traceePid),
					zap.Int("traceStep", traceStep),
					zap.String("stopCause", "STOPCAUSE_SURVEILLED_SYSCALL"),
					zap.Int("syscallStopPoint", syscallStopPoint),
				)
			}

		case STOPCAUSE_IGNORABLE:
			zap.L().Error(
				"Attending STOPCAUSE_IGNORABLE.  Cannot get tracee PGID",
				zap.Int("traceePid", traceePid),
				zap.Int("traceStep", traceStep),
				zap.String("stopCause", "STOPCAUSE_IGNORABLE"),
			)
			syscall.PtraceSyscall(traceePid, 0)

		default:
			zap.L().Fatal(
				"Unmanaged STOPCAUSE",
				zap.Int("traceePid", traceePid),
				zap.Int("stopCause", stopCause),
				zap.Int("traceStep", traceStep),
			)
		}
	}
}
