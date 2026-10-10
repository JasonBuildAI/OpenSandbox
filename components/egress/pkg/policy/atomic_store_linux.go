//go:build linux

// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// AtomicPolicyFile is the experimental runtime's durable, single-file store.
// The caller must exclusively own writes to the file and its parent directory,
// and serialize Snapshot/Save/Restore across a transaction. This is not a lock
// against other processes, a journal, or atomicity with nftables. The parent must
// be owned by the effective UID and not group/world writable. Ancestors must be
// trusted (root or effective-UID owned, and not writable by others unless sticky).
// Each operation pins the symlink-free parent and uses descriptor-relative I/O.
// Linux mount IDs (statx or /proc/self/fdinfo) are required, to reject single-file
// bind mounts even on the same device. Read-only projections and symlinks are rejected.
// Files with ACLs/xattrs/security labels and parents with access/default ACLs
// are rejected rather than silently losing metadata. Timestamps are not restored.
type AtomicPolicyFile struct {
	path string
	dir  string
	name string
	ops  atomicFileOps
}

type atomicTempFile interface {
	io.Writer
	Chown(int, int) error
	Chmod(fs.FileMode) error
	Sync() error
	Close() error
	Name() string
}

// These narrow operations keep failure classification testable, including a
// rename/unlink which took effect before returning an error.
type atomicFileOps struct {
	openDir  func(string) (*os.File, error)
	snapshot func(*os.File, string, string) (*PolicyFileSnapshot, error)
	create   func(*os.File) (atomicTempFile, error)
	rename   func(*os.File, string, string) error
	remove   func(*os.File, string) error
	syncDir  func(*os.File) error
	closeDir func(*os.File) error
}

// NewAtomicPolicyFile validates the path without changing the original file.
// Empty paths are unsupported; callers with persistence disabled should not
// construct a store. It never creates directories or migrates host mounts.
func NewAtomicPolicyFile(path string) (*AtomicPolicyFile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, atomicFileError("validate", errors.New("empty policy path"))
	}
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return nil, atomicFileError("validate", errors.New("parent traversal is unsupported"))
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, atomicFileError("validate", err)
	}
	s := &AtomicPolicyFile{path: absolute, dir: filepath.Dir(absolute), name: filepath.Base(absolute), ops: defaultAtomicFileOps()}
	if _, err := s.Snapshot(); err != nil {
		return nil, err
	}
	return s, nil
}

// Snapshot validates the supported layout and captures exact restoration data.
// Call it before any external policy effects, not only after applying nftables.
func (s *AtomicPolicyFile) Snapshot() (snapshot *PolicyFileSnapshot, err error) {
	dir, err := s.ops.openDir(s.dir)
	if err != nil {
		return nil, atomicFileError("validate-directory", err)
	}
	defer func() {
		if closeErr := s.ops.closeDir(dir); closeErr != nil {
			snapshot = nil
			err = errors.Join(err, atomicFileError("directory-close", closeErr))
		}
	}()
	snapshot, err = s.ops.snapshot(dir, s.name, s.path)
	if err != nil {
		return nil, atomicFileError("snapshot", err)
	}
	return snapshot, nil
}

// Save publishes a complete JSON image and durably records the replacement.
// Existing mode and ownership are copied to the temporary inode; a new file is
// 0600. No path is ever opened with O_TRUNC, and the original is never chmodded.
func (s *AtomicPolicyFile) Save(p *NetworkPolicy) (FileMutationState, error) {
	if p == nil {
		p = DefaultDenyPolicy()
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return FileUnchanged, atomicFileError("serialize", err)
	}
	data = append(data, '\n')
	return s.withDirectory(func(dir *os.File) (FileMutationState, error) {
		current, err := s.ops.snapshot(dir, s.name, s.path)
		if err != nil {
			return FileUnchanged, atomicFileError("snapshot", err)
		}
		return s.replace(dir, data, current)
	})
}

// Restore atomically reinstates exact bytes and metadata, or durably unlinks the
// current path when the snapshot was absent. Success does not clear any caller's
// recovery latch or prove nftables/whole-process crash consistency.
func (s *AtomicPolicyFile) Restore(snapshot *PolicyFileSnapshot) (FileMutationState, error) {
	if snapshot == nil || snapshot.path != s.path {
		return FileUnchanged, atomicFileError("validate-snapshot", errors.New("snapshot belongs to a different policy path"))
	}
	return s.withDirectory(func(dir *os.File) (FileMutationState, error) {
		current, err := s.ops.snapshot(dir, s.name, s.path)
		if err != nil {
			return FileUnchanged, atomicFileError("snapshot", err)
		}
		if snapshot.exists {
			return s.replace(dir, snapshot.data, snapshot)
		}
		state := FileUnchanged
		if current.exists {
			// An unlink error can itself be an uncertain outcome.
			state = FileUnknown
			if err := s.ops.remove(dir, s.name); err != nil {
				return state, atomicFileError("unlink", err)
			}
		}
		if err := s.ops.syncDir(dir); err != nil {
			return state, atomicFileError("directory-sync", err)
		}
		return FileCommitted, nil
	})
}

func (s *AtomicPolicyFile) withDirectory(fn func(*os.File) (FileMutationState, error)) (state FileMutationState, err error) {
	dir, err := s.ops.openDir(s.dir)
	if err != nil {
		return FileUnchanged, atomicFileError("validate-directory", err)
	}
	defer func() {
		if closeErr := s.ops.closeDir(dir); closeErr != nil {
			if state == FileCommitted {
				state = FileUnknown
			}
			err = errors.Join(err, atomicFileError("directory-close", closeErr))
		}
	}()
	return fn(dir)
}

func (s *AtomicPolicyFile) replace(dir *os.File, data []byte, metadata *PolicyFileSnapshot) (state FileMutationState, err error) {
	temp, err := s.ops.create(dir)
	if err != nil {
		return FileUnchanged, atomicFileError("create", err)
	}
	tempName := temp.Name()
	closed := false
	defer func() {
		if !closed {
			if closeErr := temp.Close(); closeErr != nil {
				err = errors.Join(err, atomicFileError("temporary-close", closeErr))
			}
		}
		if tempName != "" {
			if removeErr := s.ops.remove(dir, tempName); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				err = errors.Join(err, atomicFileError("temporary-cleanup", removeErr))
			}
		}
	}()
	if n, writeErr := temp.Write(data); writeErr != nil || n != len(data) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return FileUnchanged, atomicFileError("write", writeErr)
	}
	mode := fs.FileMode(0o600)
	if metadata.exists {
		// Chown can clear set-id bits, so apply mode after ownership.
		if err := temp.Chown(metadata.uid, metadata.gid); err != nil {
			return FileUnchanged, atomicFileError("ownership", err)
		}
		mode = metadata.mode
	}
	if err := temp.Chmod(mode); err != nil {
		return FileUnchanged, atomicFileError("mode", err)
	}
	if err := temp.Sync(); err != nil {
		return FileUnchanged, atomicFileError("file-sync", err)
	}
	closed = true
	if err := temp.Close(); err != nil {
		return FileUnchanged, atomicFileError("file-close", err)
	}
	// From the first publication attempt onward an error is never classified as
	// unchanged. In particular, remote filesystems can report a failed rename
	// after the server has already committed it.
	if err := s.ops.rename(dir, tempName, s.name); err != nil {
		return FileUnknown, atomicFileError("rename", err)
	}
	tempName = ""
	if err := s.ops.syncDir(dir); err != nil {
		return FileUnknown, atomicFileError("directory-sync", err)
	}
	return FileCommitted, nil
}

func defaultAtomicFileOps() atomicFileOps {
	return atomicFileOps{
		openDir:  securePolicyDirectory,
		snapshot: readAtomicPolicySnapshot,
		create:   createAtomicPolicyTemp,
		rename: func(dir *os.File, old, new string) error {
			return unix.Renameat(int(dir.Fd()), old, int(dir.Fd()), new)
		},
		remove:   func(dir *os.File, name string) error { return unix.Unlinkat(int(dir.Fd()), name, 0) },
		syncDir:  func(dir *os.File) error { return dir.Sync() },
		closeDir: func(dir *os.File) error { return dir.Close() },
	}
}

func securePolicyDirectory(path string) (_ *os.File, err error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if err = validatePolicyDirectoryOwner(fd, false); err != nil {
			return nil, err
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, openErr
		}
		if closeErr := unix.Close(fd); closeErr != nil {
			fd = next
			return nil, closeErr
		}
		fd = next
	}
	if err = validatePolicyDirectoryOwner(fd, true); err != nil {
		return nil, err
	}
	var statfs unix.Statfs_t
	if err = unix.Fstatfs(fd, &statfs); err != nil {
		return nil, err
	}
	if statfs.Flags&unix.ST_RDONLY != 0 {
		return nil, errors.New("read-only policy directory is unsupported")
	}
	if err = rejectPolicyDirectoryACLs(fd); err != nil {
		return nil, err
	}
	if _, err = policyMountID(fd); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validatePolicyDirectoryOwner(fd int, parent bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	euid := uint32(os.Geteuid())
	if parent {
		if st.Uid != euid || st.Mode&0o022 != 0 || st.Mode&0o300 != 0o300 {
			return errors.New("policy parent must be effective-UID owned, owner-writable/searchable, and not group/world writable")
		}
	} else if (st.Uid != 0 && st.Uid != euid) || (st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
		return errors.New("policy ancestor is not a trusted directory")
	}
	return nil
}

func policyMountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st); err == nil && st.Mask&unix.STATX_MNT_ID != 0 && st.Mnt_id != 0 {
		return st.Mnt_id, nil
	}
	// fdinfo has exposed the mount ID since Linux 3.15. Use only an already
	// pinned descriptor: device/inode equality alone cannot detect bind mounts.
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, fmt.Errorf("mount identity unavailable: %w", err)
	}
	return parsePolicyMountID(data)
}

func parsePolicyMountID(data []byte) (uint64, error) {
	var id uint64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "mnt_id:") {
			continue
		}
		if found {
			return 0, errors.New("mount identity unavailable: duplicate fdinfo mount ID")
		}
		found = true
		var err error
		id, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
		if err != nil || id == 0 {
			return 0, errors.New("mount identity unavailable: invalid fdinfo mount ID")
		}
	}
	if !found {
		return 0, errors.New("mount identity unavailable: fdinfo mount ID is missing")
	}
	return id, nil
}

func readAtomicPolicySnapshot(dir *os.File, name, path string) (_ *PolicyFileSnapshot, err error) {
	dirfd := int(dir.Fd())
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return &PolicyFileSnapshot{path: path}, nil
		}
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return nil, errors.New("policy must be a regular file with exactly one link")
	}
	parentMount, err := policyMountID(dirfd)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, f.Close()) }()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 || opened.Dev != st.Dev || opened.Ino != st.Ino {
		return nil, errors.New("policy file changed during validation")
	}
	openedMount, err := policyMountID(fd)
	if err != nil {
		return nil, err
	}
	if openedMount != parentMount {
		return nil, errors.New("policy mount changed during validation")
	}
	if err := rejectPolicyFileXattrs(fd); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	mode := fs.FileMode(opened.Mode & 0o777)
	if opened.Mode&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if opened.Mode&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if opened.Mode&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return &PolicyFileSnapshot{path: path, exists: true, data: data, mode: mode, uid: int(opened.Uid), gid: int(opened.Gid)}, nil
}

func createAtomicPolicyTemp(dir *os.File) (atomicTempFile, error) {
	for range 10 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		name := ".policy-" + hex.EncodeToString(suffix[:]) + ".tmp"
		fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := rejectPolicyFileXattrs(fd); err != nil {
			closeErr := unix.Close(fd)
			removeErr := unix.Unlinkat(int(dir.Fd()), name, 0)
			return nil, errors.Join(err, closeErr, removeErr)
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	return nil, errors.New("could not allocate a unique temporary policy file")
}

// An ACL or security label can change meaning when an inode is replaced even
// when its Unix mode and ownership match. Do not silently discard/inherit it.
func rejectPolicyFileXattrs(fd int) error {
	n, err := unix.Flistxattr(fd, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect policy extended attributes: %w", err)
	}
	if n != 0 {
		return errors.New("policy files with extended attributes, ACLs, or security labels are unsupported")
	}
	return nil
}

func rejectPolicyDirectoryACLs(fd int) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, err := unix.Fgetxattr(fd, name, nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect policy directory ACL: %w", err)
		}
		return errors.New("policy directories with access/default ACLs are unsupported")
	}
	return nil
}
