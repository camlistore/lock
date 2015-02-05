// +build !lockfileex

/*
Copyright 2013 The Go Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lock

import (
	"io"
	"syscall"
)

const (
	_FILE_ATTRIBUTE_TEMPORARY  = 0x100
	_FILE_FLAG_DELETE_ON_CLOSE = 0x04000000

	//The function requests an exclusive lock. Otherwise, it requests a shared lock.
	_LOCKFILE_EXCLUSIVE_LOCK = 0x00000002

	//The function returns immediately if it is unable to acquire the requested lock.
	//Otherwise, it waits.
	_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
)

var procLockFileEx uintptr

func init() {
	// sane default
	lockFn = lockCreateFile

	// use LockFileEx, if possible
	h, err := syscall.LoadLibrary("kernel32.dll")
	if err == nil {
	if procLockFileEx, err = syscall.GetProcAddress(h, "LockFileEx"); err != nil {
		procLockFileEx = 0
	} else {
		lockFn = lockFileEx
	}
}

type handleUnlocker struct {
	h syscall.Handle
}

func (hu *handleUnlocker) Close() error {
	return syscall.Close(hu.h)
}

func lockCreateFile(name string) (io.Closer, error) {
	pname, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858%28v=vs.85%29.aspx
	h, err := syscall.CreateFile(pname,
		syscall.GENERIC_WRITE, // open for write
		0,   // no sharing
		nil, // don't let children inherit
		syscall.CREATE_ALWAYS, // create if not exists, truncate if does
		syscall.FILE_ATTRIBUTE_NORMAL|_FILE_ATTRIBUTE_TEMPORARY|_FILE_FLAG_DELETE_ON_CLOSE,
		0)
	if err != nil {
		return nil, err
	}
	return &handleUnlocker{h}, nil
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa383751%28v=vs.85%29.aspx
type overlapped struct {
	internal, internalHigh uint64
	offset, offsetHigh     uint32
	hEvent                 uintptr
}

func lockFileEx(name string) (io.Closer, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	lockmu.Lock()
	if locked[abs] {
		lockmu.Unlock()
		return nil, fmt.Errorf("file %q already locked", abs)
	}
	locked[abs] = true
	lockmu.Unlock()

	fi, err := os.Stat(name)
	if err == nil && fi.Size() > 0 {
		return nil, fmt.Errorf("can't Lock file %q: has non-zero size", name)
	}

	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}

	// http://msdn.microsoft.com/en-us/library/aa365203.aspx
	over := overlapped{}
	r, _, e1 := syscall.Syscall6(uintptr(procLockFileEx), 6,
		uintptr(syscall.Handle(f.Fd())),
		uintptr(_LOCKFILE_EXCLUSIVE_LOCK|_LOCKFILE_FAIL_IMMEDIATELY),
		0,
		1, 0,
		uintptr(unsafe.Pointer(&over)))
	if r == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &unlocker{f, abs}, nil
}
