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

package nftables

import "errors"

// ErrQuiesced reports that this Manager no longer admits runtime nft writes.
var ErrQuiesced = errors.New("nftables manager is quiesced")

// Quiesce permanently freezes runtime writes after any current lock holder
// finishes. It does not remove enforcement or cancel an already admitted write.
func (m *Manager) Quiesce() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quiesced = true
}

func (m *Manager) isQuiesced() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.quiesced
}
