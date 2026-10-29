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
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader yields some bytes and then fails, standing in for a client
// disconnect, a short read, or an I/O error mid-copy.
type failingReader struct {
	data []byte
	err  error
	done bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.done {
		return 0, f.err
	}
	f.done = true
	n := copy(p, f.data)
	return n, nil
}

// TestMergedView_WriteFileReaderFailureKeepsTheReplacedFile is the regression
// for the isolated-session file API: the upload used to open the destination
// with O_TRUNC, so a copy that failed partway left the file it was replacing
// empty or half-written.
func TestMergedView_WriteFileReaderFailureKeepsTheReplacedFile(t *testing.T) {
	mv := newTestMergedView(t, WorkspaceRW)

	const previous = "previous content\n"
	require.NoError(t, os.WriteFile(filepath.Join(mv.UpperDir, "notes.md"), []byte(previous), 0o644))

	boom := errors.New("simulated read failure")
	_, err := mv.WriteFileReader("notes.md", &failingReader{data: []byte("partial"), err: boom}, 0o644)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)

	data, readErr := os.ReadFile(filepath.Join(mv.UpperDir, "notes.md"))
	require.NoError(t, readErr)
	assert.Equal(t, previous, string(data), "a failed write must leave the replaced file intact")
}

// TestMergedView_WriteFileReaderFailureLeavesNoNewFile covers the other half:
// a destination that did not exist before must not be left behind as an empty
// or partial file.
func TestMergedView_WriteFileReaderFailureLeavesNoNewFile(t *testing.T) {
	mv := newTestMergedView(t, WorkspaceRW)

	boom := errors.New("simulated read failure")
	_, err := mv.WriteFileReader("fresh.md", &failingReader{data: []byte("partial"), err: boom}, 0o644)
	require.Error(t, err)

	_, statErr := os.Stat(filepath.Join(mv.UpperDir, "fresh.md"))
	assert.ErrorIs(t, statErr, os.ErrNotExist, "a failed write must not create the destination")
}

// TestMergedView_WriteFileReaderNoStagingLeftBehind asserts no staging file
// survives either path, so a workspace does not accumulate hidden artifacts.
func TestMergedView_WriteFileReaderNoStagingLeftBehind(t *testing.T) {
	mv := newTestMergedView(t, WorkspaceRW)

	_, err := mv.WriteFileReader("ok.md", strings.NewReader("content"), 0o644)
	if runtime.GOOS != "windows" {
		// chown is unsupported on Windows; the staging cleanup still holds.
		require.NoError(t, err)
	}

	boom := errors.New("simulated read failure")
	_, err = mv.WriteFileReader("bad.md", &failingReader{data: []byte("x"), err: boom}, 0o644)
	require.Error(t, err)

	entries, err := os.ReadDir(mv.UpperDir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, isStagingName(entry.Name()), "staging file left behind: %s", entry.Name())
	}
}

// TestMergedView_WriteFilePreservesExistingMode keeps the permission an
// in-place truncating write preserved for free.
func TestMergedView_WriteFilePreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	mv := newTestMergedView(t, WorkspaceRW)

	target := filepath.Join(mv.UpperDir, "script.sh")
	require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Chmod(target, 0o755))

	// WriteFile takes the caller's perm, so pass the destination's own mode as
	// the isolated-session controller does after stat'ing it.
	require.NoError(t, mv.WriteFile("script.sh", []byte("#!/bin/sh\necho hi\n"), 0o755))

	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

// TestMergedView_StagingNamesHiddenFromListings ensures an in-flight or
// crashed staging file is not surfaced by the directory and search APIs.
func TestMergedView_StagingNamesHiddenFromListings(t *testing.T) {
	mv := newTestMergedView(t, WorkspaceRW)

	require.NoError(t, os.WriteFile(filepath.Join(mv.UpperDir, "visible.txt"), []byte("v"), 0o644))
	stagingName := stagingPrefix + strings.Repeat("a", stagingSuffixLen)
	require.NoError(t, os.WriteFile(filepath.Join(mv.UpperDir, stagingName), []byte("s"), 0o600))

	entries, err := mv.ReadDir(".")
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	assert.Contains(t, names, "visible.txt")
	assert.NotContains(t, names, stagingName)

	results, err := mv.Search(".", "*")
	require.NoError(t, err)
	for _, result := range results {
		assert.NotEqual(t, stagingName, filepath.Base(result), "staging file leaked into search")
	}
}

// TestStagedWriteRejectsNonRegularDestination keeps the rejection an in-place
// write had: a directory must not be replaced by a regular file.
func TestStagedWriteRejectsNonRegularDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(target, 0o755))

	err := writeFileStaged(target, []byte("x"), 0o644, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, errNotRegularFile)

	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir(), "the directory must survive a rejected write")
}

// TestStagedWriteNewFileUsesRequestedMode keeps the mode a plain create used.
func TestStagedWriteNewFileUsesRequestedMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "new.txt")

	require.NoError(t, writeFileStaged(target, []byte("data"), 0o640, false))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

// TestStagedWriteFollowsFinalSymlink keeps the bind/confined view semantics: a
// symlinked destination is written through, not replaced by a regular file.
func TestStagedWriteFollowsFinalSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o644))
	require.NoError(t, os.Symlink(target, link))

	require.NoError(t, writeFileStaged(link, []byte("new"), 0o644, true))

	linkInfo, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, linkInfo.Mode()&os.ModeSymlink, "the symlink must survive")

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data), "the link target must receive the content")
}

var _ io.Reader = (*failingReader)(nil)
