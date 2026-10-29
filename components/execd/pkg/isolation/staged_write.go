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

package isolation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// stagingPrefix names the private temp file a staged write creates next to its
// destination. The listing and search paths hide these names so an in-flight
// write, or one left behind by a killed daemon, is never returned as a user
// file.
const stagingPrefix = ".osb-staging-"

// stagingSuffixLen is the number of hex characters appended to stagingPrefix.
const stagingSuffixLen = 16

// maxSymlinkDepth bounds the final-component symlink walk; it mirrors the
// kernel's ELOOP threshold closely enough to reject a link cycle.
const maxSymlinkDepth = 40

// destinationModeMask keeps the permission bits an in-place write preserved for
// free, including setuid/setgid/sticky: a rename replaces the inode, so the
// staged file has to carry them explicitly.
const destinationModeMask = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// errNotRegularFile rejects a destination a rename cannot replace.
var errNotRegularFile = errors.New("not a regular file")

// stagingFS is the subset of os and *os.Root a staged write needs, so one
// implementation serves both the plain and the root-confined views.
type stagingFS interface {
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Readlink(name string) (string, error)
	Open(name string) (*os.File, error)
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	Chmod(name string, mode os.FileMode) error
	Rename(oldName, newName string) error
	Remove(name string) error
}

// osStagingFS adapts the package-level os functions to stagingFS.
type osStagingFS struct{}

func (osStagingFS) Stat(name string) (os.FileInfo, error)  { return os.Stat(name) }
func (osStagingFS) Lstat(name string) (os.FileInfo, error) { return os.Lstat(name) }
func (osStagingFS) Readlink(name string) (string, error)   { return os.Readlink(name) }
func (osStagingFS) Open(name string) (*os.File, error)     { return os.Open(name) }
func (osStagingFS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}
func (osStagingFS) Chmod(name string, mode os.FileMode) error { return os.Chmod(name, mode) }
func (osStagingFS) Rename(oldName, newName string) error      { return os.Rename(oldName, newName) }
func (osStagingFS) Remove(name string) error                  { return os.Remove(name) }

// isStagingName reports whether name is one of the staged-write temp files.
func isStagingName(name string) bool {
	suffix, ok := strings.CutPrefix(name, stagingPrefix)
	if !ok || len(suffix) != stagingSuffixLen {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

// hideStagingEntries removes staged-write temp files from a directory listing.
func hideStagingEntries(entries []os.DirEntry) []os.DirEntry {
	filtered := entries[:0]
	for _, entry := range entries {
		if isStagingName(entry.Name()) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// stagedWrite replaces target with the bytes produced by write.
//
// The bytes are staged in this directory and renamed into place only once they
// are fully written and synced, so a write that fails partway - ENOSPC, an I/O
// error, a short read, the daemon being killed mid-copy - leaves the file it
// was replacing intact. An in-place O_TRUNC write destroyed it, and a session
// workspace usually holds the only copy of the file a write replaces.
//
// followLink resolves a symlink in the final path component so the rename lands
// on the file an in-place write would have written through, instead of
// replacing the link itself.
func stagedWrite(fsys stagingFS, target string, perm os.FileMode, followLink bool, write func(io.Writer) (int64, error)) (int64, error) {
	if followLink {
		resolved, err := resolveFinalSymlink(fsys, target)
		if err != nil {
			return 0, err
		}
		target = resolved
	}

	existing, statErr := fsys.Stat(target)
	switch {
	case statErr == nil && !existing.Mode().IsRegular():
		// A device or a FIFO cannot be staged and renamed over without
		// replacing the node with a regular file, so refuse them.
		return 0, &os.PathError{Op: "write", Path: target, Err: errNotRegularFile}
	case statErr != nil && !errors.Is(statErr, fs.ErrNotExist):
		return 0, statErr
	}

	// An existing destination keeps its content private while it is copied
	// instead of exposing it through the staging file's mode; a new one takes
	// perm, exactly as the plain create did.
	stagingPerm := perm
	if statErr == nil {
		stagingPerm = 0o600
	}
	stagingPath, err := createStagingFile(fsys, filepath.Dir(target), stagingPerm)
	if err != nil {
		return 0, err
	}
	committed := false
	file, err := fsys.OpenFile(stagingPath, os.O_WRONLY, 0)
	if err != nil {
		_ = fsys.Remove(stagingPath)
		return 0, err
	}
	defer func() {
		if committed {
			return
		}
		_ = file.Close()
		_ = fsys.Remove(stagingPath)
	}()

	n, err := write(file)
	if err != nil {
		return n, err
	}
	if err := file.Sync(); err != nil {
		return n, err
	}
	if err := file.Close(); err != nil {
		return n, err
	}
	if statErr == nil {
		// Restore the destination mode before the rename; writing and chown
		// both clear setuid/setgid, so this must happen after the copy.
		if err := fsys.Chmod(stagingPath, existing.Mode()&destinationModeMask); err != nil {
			return n, err
		}
	}
	if err := fsys.Rename(stagingPath, target); err != nil {
		return n, err
	}
	committed = true

	// Best-effort directory fsync so the renamed entry is durable and visible
	// on weakly-coherent filesystems (virtio-fs, 9pfs, etc.). Some filesystems
	// return ENOTSUP.
	syncDir(fsys, filepath.Dir(target))
	return n, nil
}

// createStagingFile atomically creates a new staging file in dir and returns
// its path.
func createStagingFile(fsys stagingFS, dir string, perm os.FileMode) (string, error) {
	for range 10 {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", err
		}
		name := stagingPrefix + hex.EncodeToString(suffix[:])
		path := name
		if dir != "." {
			path = filepath.Join(dir, name)
		}
		file, err := fsys.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			_ = file.Close()
			return path, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("could not allocate a unique staging file name")
}

// resolveFinalSymlink follows a symlink in the final path component. Because
// every call goes through fsys, an os.Root-confined view keeps its confinement:
// an absolute target is left as-is and rejected by the root on the next step.
func resolveFinalSymlink(fsys stagingFS, path string) (string, error) {
	resolved := path
	for range maxSymlinkDepth {
		info, err := fsys.Lstat(resolved)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// A new file, or the dangling target of a link.
				return resolved, nil
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return resolved, nil
		}
		link, err := fsys.Readlink(resolved)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(resolved), link)
		}
		resolved = link
	}
	return "", fmt.Errorf("write to %s: too many levels of symbolic links", path)
}

// syncDir best-effort fsyncs dir so a renamed entry is durable.
func syncDir(fsys stagingFS, dir string) {
	d, err := fsys.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// writeFileStaged replaces target with data.
func writeFileStaged(target string, data []byte, perm os.FileMode, followLink bool) error {
	_, err := stagedWrite(osStagingFS{}, target, perm, followLink, func(w io.Writer) (int64, error) {
		n, err := w.Write(data)
		return int64(n), err
	})
	return err
}

// writeReaderStaged replaces target with the bytes read from r.
func writeReaderStaged(target string, r io.Reader, perm os.FileMode, followLink bool) (int64, error) {
	return stagedWrite(osStagingFS{}, target, perm, followLink, func(w io.Writer) (int64, error) {
		return io.Copy(w, r)
	})
}

// writeFileConfinedStaged replaces name (root-relative) with data inside root.
func writeFileConfinedStaged(root *os.Root, name string, data []byte, perm os.FileMode) error {
	_, err := stagedWrite(root, name, perm, true, func(w io.Writer) (int64, error) {
		n, err := w.Write(data)
		return int64(n), err
	})
	return err
}

// writeReaderConfinedStaged replaces name (root-relative) with r inside root.
func writeReaderConfinedStaged(root *os.Root, name string, r io.Reader, perm os.FileMode) (int64, error) {
	return stagedWrite(root, name, perm, true, func(w io.Writer) (int64, error) {
		return io.Copy(w, r)
	})
}
