// Package middleware provides request/response interception
package middleware

// Middleware defines a function that processes MCP messages
type Middleware func(msg []byte, next func([]byte) ([]byte, error)) ([]byte, error)

// Chain combines multiple middlewares into a single chain
type Chain struct {
	middlewares []Middleware
}

// New creates a new middleware chain
func New(middlewares ...Middleware) *Chain {
	return &Chain{middlewares: middlewares}
}

// Execute runs the middleware chain
func (c *Chain) Execute(msg []byte, final func([]byte) ([]byte, error)) ([]byte, error) {
	if len(c.middlewares) == 0 {
		return final(msg)
	}

	// Build the chain from end to start
	handler := final
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		mw := c.middlewares[i]
		next := handler
		handler = func(m []byte) ([]byte, error) {
			return mw(m, next)
		}
	}

	return handler(msg)
}
