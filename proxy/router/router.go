// Package router handles MCP request routing
package router

// Router manages request routing to MCP servers
type Router struct {
	routes map[string]string
}

// New creates a new Router instance
func New() *Router {
	return &Router{
		routes: make(map[string]string),
	}
}

// AddRoute registers a route to an MCP server
func (r *Router) AddRoute(pattern, target string) {
	r.routes[pattern] = target
}

// Match finds the target for a given request path
func (r *Router) Match(path string) (string, bool) {
	target, ok := r.routes[path]
	return target, ok
}
