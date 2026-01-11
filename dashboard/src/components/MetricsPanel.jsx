import { useState, useEffect } from 'react'

const mockMetrics = {
  totalRequests: 12847,
  allowRate: 94.2,
  blockRate: 3.1,
  reviewRate: 2.7,
  avgLatency: 18,
  gasUsed: 1458,
  activeTools: 142,
}

export default function MetricsPanel() {
  const [metrics, setMetrics] = useState(mockMetrics)

  // Simulate live updates
  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        totalRequests: prev.totalRequests + Math.floor(Math.random() * 3),
        avgLatency: 15 + Math.floor(Math.random() * 10),
      }))
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 overflow-hidden h-full">
      <div className="px-5 py-4 border-b border-slate-700/50">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-green-500/10 rounded-lg flex items-center justify-center">
            <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h2 className="text-lg font-semibold text-white">Metrics</h2>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Total Requests */}
        <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-lg p-4 border border-blue-500/20">
          <div className="text-sm text-slate-400">Total Requests</div>
          <div className="text-3xl font-bold text-white mt-1">{metrics.totalRequests.toLocaleString()}</div>
          <div className="text-xs text-green-400 mt-1">+127 last hour</div>
        </div>

        {/* Verdict Breakdown */}
        <div className="space-y-3">
          <div className="text-sm text-slate-400 font-medium">Verdict Distribution</div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 bg-green-500 rounded-full"></span>
                <span className="text-sm text-slate-300">Allow</span>
              </div>
              <span className="text-sm font-medium text-green-400">{metrics.allowRate}%</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-green-500 rounded-full" style={{ width: `${metrics.allowRate}%` }}></div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 bg-red-500 rounded-full"></span>
                <span className="text-sm text-slate-300">Block</span>
              </div>
              <span className="text-sm font-medium text-red-400">{metrics.blockRate}%</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-red-500 rounded-full" style={{ width: `${metrics.blockRate * 10}%` }}></div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 bg-purple-500 rounded-full"></span>
                <span className="text-sm text-slate-300">Review</span>
              </div>
              <span className="text-sm font-medium text-purple-400">{metrics.reviewRate}%</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-purple-500 rounded-full" style={{ width: `${metrics.reviewRate * 10}%` }}></div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 gap-3 pt-2">
          <div className="bg-slate-900/50 rounded-lg p-3">
            <div className="text-xs text-slate-500">Avg Latency</div>
            <div className="text-xl font-bold text-white">{metrics.avgLatency}ms</div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-3">
            <div className="text-xs text-slate-500">Active Tools</div>
            <div className="text-xl font-bold text-white">{metrics.activeTools}</div>
          </div>
        </div>
      </div>
    </div>
  )
}
