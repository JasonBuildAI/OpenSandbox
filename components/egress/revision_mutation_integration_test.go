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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/revision"
	"github.com/alibaba/opensandbox/egress/pkg/revisionruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This exercises real Store/session/Unix/Python publication, not mitmdump or TLS.
// The test stop seam signals and reaps a real child, independently of the
// production GracefulShutdown implementation and its private completion channel.
type revisionIPCChild struct {
	running *mitmproxy.Running
	input   io.WriteCloser
	output  *json.Decoder
	once    sync.Once
	stops   int
}

// Observe ordering without replacing any ProcessSession operation.
type revisionObservedSession struct {
	revisionProcessSession
	beforeClose func()
	closeOnce   sync.Once
}

func (s *revisionObservedSession) Close() error {
	s.closeOnce.Do(func() {
		if s.beforeClose != nil {
			s.beforeClose()
		}
	})
	return s.revisionProcessSession.Close()
}

type revisionChildReport struct {
	Ready             bool               `json:"ready"`
	Error             string             `json:"error"`
	Active            *revision.Identity `json:"active"`
	View              *revision.Identity `json:"view"`
	Digest            string             `json:"digest"`
	AdmissionDisabled bool               `json:"admission_disabled"`
	Counts            struct {
		Prepare  int `json:"prepare"`
		Commit   int `json:"commit"`
		Abort    int `json:"abort"`
		Readback int `json:"readback"`
		Dropped  int `json:"dropped"`
	} `json:"counts"`
}

func (c *revisionIPCChild) stop() {
	c.once.Do(func() {
		c.stops++
		_ = c.running.Cmd.Process.Signal(syscall.SIGTERM)
		reaped := make(chan struct{})
		go func() { _ = c.running.Cmd.Wait(); close(reaped) }()
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-reaped:
		case <-timer.C:
			_ = c.running.Cmd.Process.Kill()
			<-reaped
		}
		_ = c.input.Close()
	})
}

func (c *revisionIPCChild) exchange(t *testing.T, value any) revisionChildReport {
	t.Helper()
	require.NoError(t, json.NewEncoder(c.input).Encode(value))
	type result struct {
		report revisionChildReport
		err    error
	}
	done := make(chan result, 1)
	go func() {
		var report revisionChildReport
		err := c.output.Decode(&report)
		done <- result{report, err}
	}()
	select {
	case result := <-done:
		require.NoError(t, result.err, "revision integration child response unavailable")
		require.Empty(t, result.report.Error)
		return result.report
	case <-time.After(5 * time.Second):
		c.stop()
		t.Fatal("revision integration child response timed out")
		return revisionChildReport{}
	}
}

func launchRevisionIPCChild(t *testing.T, cfg mitmproxy.Config) *revisionIPCChild {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("cross-language revision integration requires python3 (installed in Egress CI)")
	}
	cmd := exec.Command(python, "tests/fixtures/revision_mutation_child.py")
	cmd.Stderr = io.Discard // Never publish a payload-bearing Python traceback.
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = input.Close() })
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = output.Close() })
	require.NoError(t, cmd.Start())
	child := &revisionIPCChild{running: &mitmproxy.Running{Cmd: cmd}, input: input, output: json.NewDecoder(output)}
	t.Cleanup(child.stop)
	require.True(t, child.exchange(t, cfg.RevisionIPC).Ready)
	return child
}

func revisionIntegrationServer(t *testing.T) *policyServer {
	t.Helper()
	t.Setenv(constants.EnvMitmproxyTransparent, "true")
	pol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example.com"}]}`)
	require.NoError(t, err)
	return &policyServer{proxy: &stubProxy{updated: pol}, mitmGate: mitmproxy.NewHealthGate(), credentialVault: credentialvault.NewStore(nil, func() bool { return true })}
}

func revisionIntegrationLaunch(t *testing.T, s *policyServer) (*mitmTransparent, *revisionIPCChild, *mitmproxy.RevisionIPCConfig) {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "osri-owner-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(parent)) })
	var child *revisionIPCChild
	owner := &revisionLaunchOwner{
		config: revisionruntime.ProcessSessionConfig{ParentDir: parent, UID: os.Getuid(), GID: os.Getgid(), SubjectGeneration: "integration-subject", MaxSnapshotBytes: 65536},
		newSession: func(config revisionruntime.ProcessSessionConfig) (revisionProcessSession, error) {
			session, err := newRevisionProcessSession(config)
			if err == nil {
				t.Cleanup(func() {
					if child != nil {
						child.stop()
					}
					require.NoError(t, session.Close())
				})
			}
			if err != nil {
				return nil, err
			}
			return &revisionObservedSession{revisionProcessSession: session}, nil
		},
		snapshot: func(ctx context.Context) (credentialvault.ActiveSnapshot, int64, *revisionBootstrapTicket, error) {
			snapshot, epoch, err := s.revisionBootstrapSnapshot(ctx)
			return snapshot, epoch, nil, err
		},
		stop: func(r *mitmproxy.Running) {
			assert.Same(t, child.running, r)
			child.stop()
			assert.NotNil(t, r.Cmd.ProcessState, "child must be reaped before session cleanup")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := owner.launch(ctx, mitmproxy.Config{}, func(cfg mitmproxy.Config) (*mitmproxy.Running, error) {
		child = launchRevisionIPCChild(t, cfg)
		return child.running, nil
	})
	require.NoError(t, err)
	running, session := result.running, result.session
	config, err := session.MitmproxyConfig()
	require.NoError(t, err)
	t.Cleanup(func() { child.stop(); require.NoError(t, session.Close()) })
	s.mitmGate.SetReady(true)
	return &mitmTransparent{running: running, revisionSession: session, revisionOwner: owner, currentGen: 1}, child, config
}

func integrationVaultRequest(secret string) credentialvault.CreateRequest {
	source, _ := json.Marshal(map[string]string{"type": "inline", "value": secret})
	return credentialvault.CreateRequest{
		Credentials: []credentialvault.Credential{{Name: "token", Source: source}},
		Bindings:    []credentialvault.Binding{{Name: "api", Match: credentialvault.Match{Hosts: []string{"api.example.com"}}, Auth: credentialvault.Auth{Type: "apiKey", Name: "X-API-Key", Credential: "token"}}},
	}
}

func assertRevisionChildSnapshot(t *testing.T, child *revisionIPCChild, snapshot credentialvault.ActiveSnapshot) revisionChildReport {
	t.Helper()
	report := child.exchange(t, map[string]string{"command": "inspect"})
	payload, err := credentialvault.MarshalDecisionSnapshot(snapshot, 0)
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	require.NotNil(t, report.Active)
	require.Equal(t, report.Active, report.View)
	require.Equal(t, hex.EncodeToString(digest[:]), report.Digest)
	require.Equal(t, report.Digest, report.Active.Digest)
	require.Equal(t, snapshot.Revision, report.Active.VaultRevision)
	require.Zero(t, report.Active.PolicyEpoch)
	require.True(t, report.AdmissionDisabled)
	return report
}

func TestRevisionVaultMutationIPCChildLifecycle(t *testing.T) {
	s := revisionIntegrationServer(t)
	m, child, config := revisionIntegrationLaunch(t, s)
	initial := assertRevisionChildSnapshot(t, child, credentialvault.ActiveSnapshot{})
	require.Equal(t, config.ControlGeneration, initial.Active.ControlGeneration)
	require.Equal(t, config.SubjectGeneration, initial.Active.SubjectGeneration)
	require.Equal(t, int64(1), initial.Active.DecisionEpoch)
	for index, step := range []string{"create", "patch", "delete", "recreate"} {
		_, err := s.mutateRevisionVault(mutationContext(t), m, func(store *credentialvault.Store, pol *policy.NetworkPolicy) (*credentialvault.MutationCandidate, error) {
			switch step {
			case "patch":
				credentials := integrationVaultRequest("private-rotated").Credentials
				return store.PreparePatch(credentialvault.MutationRequest{Credentials: &credentialvault.CredentialMutationSet{Replace: credentials}}, pol)
			case "delete":
				return store.PrepareDelete()
			default:
				return store.PrepareCreate(integrationVaultRequest("private-original"), pol)
			}
		})
		require.NoError(t, err)
		snapshot, err := s.credentialVault.ActiveSnapshot()
		if step == "delete" {
			require.ErrorIs(t, err, credentialvault.ErrNotFound)
		} else {
			require.NoError(t, err)
		}
		report := assertRevisionChildSnapshot(t, child, snapshot)
		require.Equal(t, index+2, report.Counts.Prepare)
		require.Equal(t, index+2, report.Counts.Commit)
		require.Equal(t, int64(index+2), report.Active.DecisionEpoch)
		require.Equal(t, config.ControlGeneration, report.Active.ControlGeneration)
		require.Equal(t, config.SubjectGeneration, report.Active.SubjectGeneration)
		require.False(t, s.mitmGate.MitmPending())
	}
}

func TestRevisionVaultMutationIPCChildLostCommitReply(t *testing.T) {
	s := revisionIntegrationServer(t)
	m, child, _ := revisionIntegrationLaunch(t, s)
	require.True(t, child.exchange(t, map[string]string{"command": "fault", "mode": "drop-commit"}).Ready)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() { cancel(); <-finished })
	go func() {
		defer close(finished)
		_, err := s.mutateRevisionVault(ctx, m, func(store *credentialvault.Store, pol *policy.NetworkPolicy) (*credentialvault.MutationCandidate, error) {
			return store.PrepareCreate(integrationVaultRequest("private-confirmed"), pol)
		})
		done <- err
	}()
	require.True(t, child.exchange(t, map[string]string{"command": "await-readback"}).Ready)
	_, err := s.credentialVault.Sanitized()
	require.ErrorIs(t, err, credentialvault.ErrNotFound, "remote commit must not publish before its acknowledgement")
	reportBefore := child.exchange(t, map[string]string{"command": "inspect"})
	require.NotNil(t, reportBefore.Active)
	require.Equal(t, int64(1), reportBefore.Active.VaultRevision)
	require.True(t, child.exchange(t, map[string]string{"command": "release"}).Ready)
	require.NoError(t, <-done)
	snapshot, err := s.credentialVault.ActiveSnapshot()
	require.NoError(t, err)
	report := assertRevisionChildSnapshot(t, child, snapshot)
	require.Equal(t, 1, report.Counts.Dropped)
	require.Equal(t, 2, report.Counts.Prepare) // bootstrap and exactly one candidate
	require.Equal(t, 2, report.Counts.Commit)
	require.GreaterOrEqual(t, report.Counts.Readback, 2) // freshness plus reconciliation
	require.Zero(t, child.stops)
}

func TestRevisionVaultMutationIPCChildRecovery(t *testing.T) {
	for _, fault := range []string{"unresolved", "stale-finalization"} {
		t.Run(fault, func(t *testing.T) {
			s := revisionIntegrationServer(t)
			_, err := s.credentialVault.Create(integrationVaultRequest("private-retained"), s.effectivePolicy())
			require.NoError(t, err)
			m, child, oldConfig := revisionIntegrationLaunch(t, s)
			oldSession := m.revisionSession
			stopEntered := make(chan struct{})
			releaseStop := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseStop) }) }
			t.Cleanup(release)
			stop := m.revisionOwner.stop
			m.revisionOwner.stop = func(r *mitmproxy.Running) {
				close(stopEntered)
				<-releaseStop
				stop(r)
			}
			if fault == "unresolved" {
				require.True(t, child.exchange(t, map[string]string{"command": "fault", "mode": "unresolved"}).Ready)
			}
			var candidate *credentialvault.MutationCandidate
			closeAfterReap := false
			closeBeforeDiscard := false
			oldSession.(*revisionObservedSession).beforeClose = func() {
				closeAfterReap = child.running.Cmd.ProcessState != nil
				_, candidateErr := candidate.Sanitized()
				closeBeforeDiscard = candidateErr == nil || fault == "stale-finalization" && candidateErr == credentialvault.ErrCandidateClosed
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			finished := make(chan struct{})
			t.Cleanup(func() { cancel(); release(); <-finished })
			go func() {
				defer close(finished)
				_, mutationErr := s.mutateRevisionVault(ctx, m, func(store *credentialvault.Store, pol *policy.NetworkPolicy) (*credentialvault.MutationCandidate, error) {
					var err error
					candidate, err = store.PreparePatch(credentialvault.MutationRequest{Credentials: &credentialvault.CredentialMutationSet{Replace: integrationVaultRequest("private-unpublished").Credentials}}, pol)
					if err == nil && fault == "stale-finalization" {
						// Deterministically advance the public mutation tag after prepare.
						_, err = store.Patch(credentialvault.MutationRequest{Credentials: &credentialvault.CredentialMutationSet{Replace: integrationVaultRequest("private-retained").Credentials}}, pol)
					}
					return candidate, err
				})
				done <- mutationErr
			}()
			if fault == "unresolved" {
				require.True(t, child.exchange(t, map[string]string{"command": "await-readback"}).Ready)
				report := child.exchange(t, map[string]string{"command": "inspect"})
				require.Equal(t, 1, report.Counts.Dropped)
				require.NotNil(t, report.Active)
				require.Equal(t, int64(2), report.Active.VaultRevision)
				require.True(t, child.exchange(t, map[string]string{"command": "release"}).Ready) // deliver failed readbacks until the actual deadline
			}
			select {
			case <-stopEntered:
			case <-time.After(5 * time.Second):
				t.Fatal("terminal cleanup did not start")
			}
			require.True(t, s.mitmGate.MitmPending())
			require.Nil(t, m.running)
			require.Nil(t, m.revisionSession)
			policyLocked := !s.mu.TryLock()
			if !policyLocked {
				s.mu.Unlock()
			}
			require.True(t, policyLocked, "policy barrier must cover child cleanup")
			lifecycleLocked := !m.mu.TryLock()
			if !lifecycleLocked {
				m.mu.Unlock()
			}
			require.True(t, lifecycleLocked, "lifecycle barrier must cover child cleanup")
			_, err = candidate.Sanitized()
			if fault == "unresolved" {
				require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
				require.NoError(t, err, "candidate must remain alive until child is reaped")
			} else {
				require.ErrorIs(t, err, credentialvault.ErrCandidateClosed)
			}
			require.DirExists(t, filepath.Dir(oldConfig.SocketPath))
			if fault == "stale-finalization" {
				installed := child.exchange(t, map[string]string{"command": "inspect"})
				require.Equal(t, 2, installed.Counts.Commit)
				require.NotNil(t, installed.Active)
				require.Equal(t, int64(2), installed.Active.VaultRevision)
			}
			cleanupSeen := make(chan bool, 1)
			go func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				_, candidateErr := candidate.Sanitized()
				_, sessionErr := oldSession.MitmproxyConfig()
				cleanupSeen <- candidateErr == credentialvault.ErrCandidateClosed && sessionErr == revision.ErrClosed && child.running.Cmd.ProcessState != nil
			}()
			release()
			err = <-done
			require.True(t, <-cleanupSeen, "candidate discard, session close and child reap must precede policy unlock")
			require.ErrorIs(t, err, revision.ErrTransportUnavailable)
			require.Equal(t, 1, child.stops)
			require.True(t, closeAfterReap, "session must close only after child reaping")
			require.True(t, closeBeforeDiscard, "unresolved candidate must survive through child cleanup")
			require.NotNil(t, child.running.Cmd.ProcessState)
			require.Nil(t, m.running)
			require.Nil(t, m.revisionSession)
			require.True(t, s.mitmGate.MitmPending())
			require.NoDirExists(t, filepath.Dir(oldConfig.SocketPath))
			_, err = oldSession.MitmproxyConfig()
			require.ErrorIs(t, err, revision.ErrClosed)
			_, err = candidate.Sanitized()
			require.ErrorIs(t, err, credentialvault.ErrCandidateClosed)
			prior, err := s.credentialVault.ActiveSnapshot()
			require.NoError(t, err)
			require.True(t, prior.Bindings[0].Headers[0].Value == "private-retained", "public Store must retain the prior credential")
			_, fresh, freshConfig := revisionIntegrationLaunch(t, s)
			require.NotEqual(t, oldConfig.ControlGeneration, freshConfig.ControlGeneration)
			require.True(t, oldConfig.SessionToken != freshConfig.SessionToken, "fresh session must rotate authentication token")
			report := assertRevisionChildSnapshot(t, fresh, prior)
			require.Equal(t, int64(1), report.Active.DecisionEpoch)
			require.Equal(t, freshConfig.ControlGeneration, report.Active.ControlGeneration)
			require.Equal(t, 1, child.stops)
		})
	}
}

func TestRevisionVaultMutationIPCChildLostPrepareReplyAborts(t *testing.T) {
	s := revisionIntegrationServer(t)
	_, err := s.credentialVault.Create(integrationVaultRequest("private-retained"), s.effectivePolicy())
	require.NoError(t, err)
	prior, err := s.credentialVault.ActiveSnapshot()
	require.NoError(t, err)
	m, child, _ := revisionIntegrationLaunch(t, s)
	running := m.running
	require.True(t, child.exchange(t, map[string]string{"command": "fault", "mode": "drop-prepare"}).Ready)
	_, err = s.mutateRevisionVault(mutationContext(t), m, func(store *credentialvault.Store, pol *policy.NetworkPolicy) (*credentialvault.MutationCandidate, error) {
		return store.PreparePatch(credentialvault.MutationRequest{Credentials: &credentialvault.CredentialMutationSet{Replace: integrationVaultRequest("private-aborted").Credentials}}, pol)
	})
	require.ErrorIs(t, err, revision.ErrPrepareRejected)
	retained, err := s.credentialVault.ActiveSnapshot()
	require.NoError(t, err)
	require.Equal(t, prior.Revision, retained.Revision)
	report := assertRevisionChildSnapshot(t, child, prior)
	assertRevisionChildSnapshot(t, child, retained)
	require.Equal(t, 2, report.Counts.Prepare)
	require.Equal(t, 1, report.Counts.Commit)
	require.Equal(t, 1, report.Counts.Abort)
	require.Equal(t, 1, report.Counts.Dropped)
	require.Same(t, running, m.running)
	require.False(t, s.mitmGate.MitmPending())
	require.Zero(t, child.stops)
}

// No socket required: verify the fixture's real child cleanup and KILL fallback
// even in environments that cannot execute the IPC integration cases.
func TestRevisionIPCChildStopReapsProcess(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("child cleanup test requires python3")
	}
	for _, disposition := range []string{"SIG_DFL", "SIG_IGN"} {
		t.Run(disposition, func(t *testing.T) {
			cmd := exec.Command(python, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal."+disposition+"); print('{\"ready\":true}', flush=True); time.sleep(60)")
			input, err := cmd.StdinPipe()
			require.NoError(t, err)
			t.Cleanup(func() { _ = input.Close() })
			output, err := cmd.StdoutPipe()
			require.NoError(t, err)
			t.Cleanup(func() { _ = output.Close() })
			require.NoError(t, cmd.Start())
			child := &revisionIPCChild{running: &mitmproxy.Running{Cmd: cmd}, input: input, output: json.NewDecoder(output)}
			t.Cleanup(child.stop)
			require.True(t, child.exchange(t, map[string]string{}).Ready)
			child.stop()
			child.stop()
			require.Equal(t, 1, child.stops)
			require.NotNil(t, cmd.ProcessState)
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			require.True(t, ok)
			expected := syscall.SIGTERM
			if disposition == "SIG_IGN" {
				expected = syscall.SIGKILL
			}
			require.Equal(t, expected, status.Signal())
		})
	}
}
