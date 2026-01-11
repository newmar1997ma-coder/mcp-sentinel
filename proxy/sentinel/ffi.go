//go:build ffi

// FFI implementation using cgo to call Rust sentinel crates.
// Build with: CGO_ENABLED=1 go build -tags ffi ./...

package sentinel

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lsentinel_ffi

// check_registry validates a schema against the registry
// Returns 1 if valid, 0 if invalid
extern int check_registry(const char* schema_json, int len);

// check_state validates state transitions
// Returns 1 if valid, 0 if cycle detected or gas exceeded
extern int check_state(const char* state_json, int len);

// vote_council submits an action for consensus voting
// Returns 1 if approved, 0 if rejected
extern int vote_council(const char* action_json, int len);

// get_last_error returns the last error message
// Caller must free the returned string
extern char* get_last_error();

// free_string frees a string allocated by Rust
extern void free_string(char* s);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

// ffiImpl provides FFI-based implementations calling Rust.
type ffiImpl struct {
	mu sync.Mutex
}

// newClientImpl returns the FFI implementation.
func newClientImpl() clientImpl {
	return &ffiImpl{}
}

func (f *ffiImpl) checkRegistry(req *RegistryCheckRequest) (*CheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal request: %w", err)
	}

	cData := C.CString(string(data))
	defer C.free(unsafe.Pointer(cData))

	result := C.check_registry(cData, C.int(len(data)))
	if result == 0 {
		errMsg := f.getLastError()
		return &CheckResult{
			Allowed: false,
			Reason:  errMsg,
		}, nil
	}

	return &CheckResult{
		Allowed: true,
		Reason:  "registry validation passed",
	}, nil
}

func (f *ffiImpl) checkState(req *StateCheckRequest) (*CheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal request: %w", err)
	}

	cData := C.CString(string(data))
	defer C.free(unsafe.Pointer(cData))

	result := C.check_state(cData, C.int(len(data)))
	if result == 0 {
		errMsg := f.getLastError()
		return &CheckResult{
			Allowed: false,
			Reason:  errMsg,
		}, nil
	}

	return &CheckResult{
		Allowed: true,
		Reason:  "state validation passed",
	}, nil
}

func (f *ffiImpl) voteCouncil(req *CouncilVoteRequest) (*CheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal request: %w", err)
	}

	cData := C.CString(string(data))
	defer C.free(unsafe.Pointer(cData))

	result := C.vote_council(cData, C.int(len(data)))
	if result == 0 {
		errMsg := f.getLastError()
		return &CheckResult{
			Allowed: false,
			Reason:  errMsg,
		}, nil
	}

	return &CheckResult{
		Allowed: true,
		Reason:  "council approved action",
	}, nil
}

func (f *ffiImpl) getLastError() string {
	errStr := C.get_last_error()
	if errStr == nil {
		return "unknown error"
	}
	defer C.free_string(errStr)
	return C.GoString(errStr)
}
