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

package credentialvault

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicySnapshotPreservesRenderedVault(t *testing.T) {
	var resolves atomic.Int32
	registry := NewSourceRegistry()
	registry.Register("rotating-candidate", func(json.RawMessage) (CredentialSource, error) {
		return &rotatingCandidateSource{resolves: &resolves}, nil
	})
	store := NewStoreWithRegistry(nil, nil, registry)
	pol := testCredentialPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"code.example.com"}]}`)
	req := testCredentialVaultRequest()
	req.Credentials[0].Source = json.RawMessage(`{"type":"rotating-candidate"}`)
	mutation, err := store.PrepareCreate(req, pol)
	require.NoError(t, err)
	before, err := mutation.ActiveSnapshot(context.Background())
	require.NoError(t, err)
	state, err := store.CommitCandidate(mutation)
	require.NoError(t, err)
	frozen, err := store.FreezeForPolicy(pol)
	require.NoError(t, err)
	require.True(t, frozen.Exists())
	require.Equal(t, before, frozen.Snapshot())
	require.Equal(t, int32(1), resolves.Load())
	got := frozen.Snapshot()
	got.Bindings[0].Headers[0].Value = "tampered"
	got.Bindings[0].Match.Hosts[0] = "tampered.example.com"
	require.Equal(t, before, frozen.Snapshot())
	require.NoError(t, store.ValidatePolicySnapshot(frozen))
	after, err := store.Sanitized()
	require.NoError(t, err)
	require.Equal(t, state, after)
	require.NotContains(t, fmt.Sprintf("%v %#v %v %#v", frozen, frozen, *frozen, *frozen), "resolved-secret")
	require.ErrorIs(t, NewStore(nil, nil).ValidatePolicySnapshot(frozen), ErrInvalidCandidate)
	require.NoError(t, store.Delete())
	require.ErrorIs(t, store.ValidatePolicySnapshot(frozen), ErrStaleCandidate)
	_, err = store.Create(req, pol)
	require.NoError(t, err)
	require.ErrorIs(t, store.ValidatePolicySnapshot(frozen), ErrStaleCandidate)
}

func TestPolicySnapshotAbsentEmptyAndUnrendered(t *testing.T) {
	pol := testCredentialPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"code.example.com"}]}`)
	store := NewStore(nil, nil)
	absent, err := store.FreezeForPolicy(pol)
	require.NoError(t, err)
	require.False(t, absent.Exists())
	require.Zero(t, absent.Snapshot().Revision)
	_, err = store.Create(CreateRequest{}, pol)
	require.NoError(t, err)
	empty, err := store.FreezeForPolicy(pol)
	require.NoError(t, err)
	require.True(t, empty.Exists())
	require.Equal(t, int64(1), empty.Snapshot().Revision)
	require.ErrorIs(t, store.ValidatePolicySnapshot(absent), ErrStaleCandidate)
	require.NoError(t, store.Delete())
	_, err = store.Create(testCredentialVaultRequest(), pol)
	require.NoError(t, err)
	_, err = store.FreezeForPolicy(pol)
	require.ErrorIs(t, err, ErrCandidateNotRendered)
	_, err = store.ActiveSnapshot()
	require.NoError(t, err)
	_, err = store.FreezeForPolicy(pol)
	require.ErrorIs(t, err, ErrCandidateNotRendered)
}

func TestPolicySnapshotRevalidatesWholeVault(t *testing.T) {
	store := NewStore(nil, nil)
	allow := testCredentialPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"*.example.com"}]}`)
	req := testCredentialVaultRequest()
	req.Bindings[0].Match.Hosts = []string{"*.example.com"}
	mutation, err := store.PrepareCreate(req, allow)
	require.NoError(t, err)
	_, err = mutation.ActiveSnapshot(context.Background())
	require.NoError(t, err)
	_, err = store.CommitCandidate(mutation)
	require.NoError(t, err)
	for _, raw := range []string{
		`{"defaultAction":"deny","egress":[{"action":"deny","target":"secret.example.com"},{"action":"allow","target":"*.example.com"}]}`,
		`{"defaultAction":"deny","egress":[{"action":"deny","target":"*.secret.example.com"},{"action":"allow","target":"*.example.com"}]}`,
	} {
		deny := testCredentialPolicy(t, raw)
		_, err = store.FreezeForPolicy(deny)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "secret-token")
	}
	_, err = store.FreezeForPolicy(allow)
	require.NoError(t, err)
}

func TestPolicySnapshotRevalidatesHTTPOnlyAndCredentialReferences(t *testing.T) {
	store := NewStore(nil, nil)
	allow := testCredentialPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"*.example.com"}]}`)
	req := testCredentialVaultRequest()
	other := req.Bindings[0]
	other.Name = "http-only"
	other.Match = Match{Hosts: []string{"http.example.com"}, Schemes: []string{"http"}}
	req.Bindings = append(req.Bindings, other)
	mutation, err := store.PrepareCreate(req, allow)
	require.NoError(t, err)
	before, err := mutation.ActiveSnapshot(context.Background())
	require.NoError(t, err)
	state, err := store.CommitCandidate(mutation)
	require.NoError(t, err)
	frozen, err := store.FreezeForPolicy(allow)
	require.NoError(t, err)
	narrowed := testCredentialPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"code.example.com"}]}`)
	_, err = store.FreezeForPolicy(narrowed)
	require.ErrorIs(t, err, ErrInvalidCandidate)
	require.NoError(t, store.ValidatePolicySnapshot(frozen))
	after, err := store.Sanitized()
	require.NoError(t, err)
	require.Equal(t, state, after)
	rendered, err := store.ActiveSnapshot()
	require.NoError(t, err)
	require.Equal(t, before, rendered)
	store.mu.Lock()
	delete(store.credentials, "gitlab-token")
	store.mu.Unlock()
	_, err = store.FreezeForPolicy(allow)
	require.ErrorIs(t, err, ErrInvalidCandidate)
}

func TestPolicySnapshotConcurrentCaptureIsCoherent(t *testing.T) {
	store := NewStore(nil, nil)
	pol := testCredentialPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"code.example.com"}]}`)
	req := testCredentialVaultRequest()
	req.Credentials[0].Source = json.RawMessage(`{"type":"inline","value":"snapshot-1"}`)
	first, err := store.PrepareCreate(req, pol)
	require.NoError(t, err)
	_, err = first.ActiveSnapshot(context.Background())
	require.NoError(t, err)
	_, err = store.CommitCandidate(first)
	require.NoError(t, err)
	finished := make(chan error, 1)
	go func() {
		for revision := 2; revision <= 50; revision++ {
			source, _ := json.Marshal(map[string]string{"type": "inline", "value": fmt.Sprintf("snapshot-%d", revision)})
			mutation, err := store.PreparePatch(MutationRequest{Credentials: &CredentialMutationSet{Replace: []Credential{{Name: "gitlab-token", Source: source}}}}, pol)
			if err == nil {
				_, err = mutation.ActiveSnapshot(context.Background())
			}
			if err == nil {
				_, err = store.CommitCandidate(mutation)
			}
			if err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	for {
		frozen, err := store.FreezeForPolicy(pol)
		require.NoError(t, err)
		snapshot := frozen.Snapshot()
		require.Equal(t, fmt.Sprintf("snapshot-%d", snapshot.Revision), snapshot.Bindings[0].Headers[0].Value)
		store.mu.RLock()
		if frozen.mutationTag == store.mutationTag {
			require.Equal(t, store.revision, snapshot.Revision)
			require.Equal(t, *store.activeSnapshot, snapshot)
		}
		store.mu.RUnlock()
		select {
		case err := <-finished:
			require.NoError(t, err)
			return
		default:
		}
	}
}

func TestPolicySnapshotAbsentABARemainsStale(t *testing.T) {
	store := NewStore(nil, nil)
	frozen, err := store.FreezeForPolicy(nil)
	require.NoError(t, err)
	_, err = store.Create(CreateRequest{}, nil)
	require.NoError(t, err)
	require.NoError(t, store.Delete())
	require.ErrorIs(t, store.ValidatePolicySnapshot(frozen), ErrStaleCandidate)
	require.False(t, frozen.Exists())
	require.Zero(t, frozen.Snapshot().Revision)
}
