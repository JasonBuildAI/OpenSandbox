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
	"errors"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/revision"
)

// mutateRevisionVault is an internal, HTTP-unwired installation transaction.
// It does not provide transport drain acknowledgements or policy epoch updates.
// prepare must only prepare a candidate from the supplied Store and policy; it
// must not publish state or reenter policy/lifecycle methods. The caller must
// supply a deadline context canceled when sidecar shutdown begins.
//
// Lock order is policy barrier -> exclusive process lease. Both stay held from
// candidate preparation through local finalization or terminal cleanup. Unlike
// withRevisionMutationSession, this owner can detach failed resources without a
// lock upgrade. Recovery directly stops/reaps the exact child before closing its
// session and discarding the candidate. It never calls lifecycle lock methods.
// IPC is context-bounded, but existing stop/reap has no hard recovery deadline.
func (s *policyServer) mutateRevisionVault(
	ctx context.Context, m *mitmTransparent,
	prepare func(*credentialvault.Store, *policy.NetworkPolicy) (*credentialvault.MutationCandidate, error),
) (credentialvault.State, error) {
	empty := credentialvault.State{}
	if s == nil || m == nil || ctx == nil || prepare == nil || s.credentialVault == nil || s.proxy == nil || s.mitmGate == nil {
		return empty, revision.ErrInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return empty, revision.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.revisionRecovery.recoveryErrorLocked(); err != nil {
		return empty, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if m.stopping {
		return empty, revision.ErrClosed
	}
	if m.running == nil || m.revisionSession == nil || m.revisionOwner == nil || m.revisionOwner.stop == nil || s.mitmGate.MitmPending() {
		return empty, revision.ErrTransportUnavailable
	}
	candidate, err := prepare(s.credentialVault, s.effectivePolicy())
	if err != nil || candidate == nil {
		if candidate != nil {
			candidate.Discard()
		}
		return empty, revision.ErrInvalid
	}
	defer candidate.Discard()
	snapshot, err := candidate.ActiveSnapshot(ctx)
	if err != nil {
		return empty, revision.ErrInvalid
	}
	// Policy epoch remains the bootstrap-reserved zero until policy integration.
	payload, err := credentialvault.MarshalDecisionSnapshot(snapshot, 0)
	if err != nil {
		return empty, revision.ErrInvalid
	}
	digest := sha256.Sum256(payload)
	session := m.revisionSession
	detach := func() (credentialvault.State, error) {
		s.mitmGate.SetReady(false)
		running := m.running
		m.running, m.revisionSession = nil, nil
		// Keep currentGen: the exact child's exit event drives fresh bootstrap, whose
		// snapshot must wait for s.mu. Concurrent shutdown also waits for this lease.
		m.revisionOwner.stop(running)
		// Close failures remain a failed transaction. Do not expose error text that
		// may contain credentials or filesystem details, or restore readiness here.
		if err := session.Close(); err != nil && s.revisionRecovery != nil {
			s.requireRevisionRecoveryLocked(revisionRecoverySessionCleanupFailed)
		}
		return empty, revision.ErrTransportUnavailable
	}
	config, err := session.MitmproxyConfig()
	if err != nil || config == nil {
		return detach()
	}
	matches := func(id revision.Identity) bool {
		return config.ControlGeneration != "" && config.SubjectGeneration != "" &&
			id.ControlGeneration == config.ControlGeneration && id.SubjectGeneration == config.SubjectGeneration &&
			id.DecisionEpoch > 0 && id.VaultRevision == snapshot.Revision && id.PolicyEpoch == 0 &&
			id.Digest == hex.EncodeToString(digest[:])
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	attempt, err := session.Update(ctx, snapshot, 0)
	if err != nil && !errors.Is(err, revision.ErrIndeterminate) {
		if errors.Is(err, revision.ErrPrepareRejected) {
			return empty, revision.ErrPrepareRejected
		}
		return detach()
	}
	if !matches(attempt) {
		return detach()
	}
	for err != nil {
		if ctx.Err() != nil {
			return detach()
		}
		var committed bool
		committed, err = session.ReconcileUpdate(ctx, attempt)
		if err == nil {
			if !committed {
				return empty, revision.ErrPrepareRejected
			}
			break
		}
		if errors.Is(err, revision.ErrClosed) || errors.Is(err, revision.ErrTransportUnavailable) || errors.Is(err, revision.ErrInvalid) {
			return detach()
		}
		// Do not spin on unavailable readback or send Update again. Reconcile only
		// this exact attempt until confirmation or the caller's bounded deadline.
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return detach()
		case <-timer.C:
		}
	}
	state, err := s.credentialVault.CommitCandidate(candidate)
	if err != nil {
		return detach()
	}
	return state, nil
}
