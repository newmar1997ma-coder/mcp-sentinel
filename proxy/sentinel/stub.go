//go:build !ffi

// Stub implementation used when building without Rust FFI.
// All security checks pass immediately. This is the default build mode.

package sentinel

// stubImpl provides stub implementations that always allow.
type stubImpl struct{}

// newClientImpl returns the stub implementation.
func newClientImpl() clientImpl {
	return &stubImpl{}
}

func (s *stubImpl) checkRegistry(req *RegistryCheckRequest) (*CheckResult, error) {
	return &CheckResult{
		Allowed: true,
		Reason:  "stub: registry check bypassed",
		Details: map[string]interface{}{
			"mode":     "stub",
			"tool":     req.ToolName,
			"schema":   req.SchemaID,
			"server":   req.ServerID,
		},
	}, nil
}

func (s *stubImpl) checkState(req *StateCheckRequest) (*CheckResult, error) {
	return &CheckResult{
		Allowed: true,
		Reason:  "stub: state check bypassed",
		Details: map[string]interface{}{
			"mode":      "stub",
			"session":   req.SessionID,
			"tool":      req.ToolName,
			"depth":     req.CallDepth,
			"gas_used":  req.GasUsed,
		},
	}, nil
}

func (s *stubImpl) voteCouncil(req *CouncilVoteRequest) (*CheckResult, error) {
	return &CheckResult{
		Allowed: true,
		Reason:  "stub: council vote bypassed",
		Details: map[string]interface{}{
			"mode":       "stub",
			"action":     req.Action,
			"tool":       req.ToolName,
			"risk_score": req.RiskScore,
		},
	}, nil
}
