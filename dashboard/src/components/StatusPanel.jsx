import { useState, useEffect } from 'react'

const components = [
  {
    name: 'Registry Guard',
    status: 'healthy',
    icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    stats: { tools: 142, driftEvents: 0 }
  },
  {
    name: 'State Monitor',
    status: 'healthy',
    icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
    stats: { gasRemaining: '8,542 / 10,000', cycles: 0 }
  },
  {
    name: 'Cognitive Council',
    status: 'healthy',
    icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z',
    stats: { evaluators: 3, waluigi: 'Active' }
  },
  {
    name: 'Semantic Firewall',
    status: 'healthy',
    icon: 'M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z',
    stats: { patterns: 12, entropy: 4.5 }
  },
]

const statusColors = {
  healthy: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', dot: 'bg-green-500' },
  warning: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', dot: 'bg-red-500' },
}

export default function StatusPanel() {
  const [uptime, setUptime] = useState('2d 14h 32m')

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-700/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-500/10 rounded-lg flex items-center justify-center">
            <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2 className="text-lg font-semibold text-white">System Status</h2>
        </div>
        <div className="text-sm text-slate-400">
          Uptime: <span className="text-slate-200 font-medium">{uptime}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 p-5">
        {components.map((component) => {
          const colors = statusColors[component.status]
          return (
            <div
              key={component.name}
              className={`${colors.bg} ${colors.border} border rounded-lg p-4 transition-all hover:scale-[1.02]`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-slate-700/50 rounded-lg flex items-center justify-center">
                    <svg className={`w-4 h-4 ${colors.text}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={component.icon} />
                    </svg>
                  </div>
                  <span className="font-medium text-white text-sm">{component.name}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className={`w-2 h-2 ${colors.dot} rounded-full`}></span>
                  <span className={`text-xs font-medium ${colors.text} capitalize`}>{component.status}</span>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(component.stats).map(([key, value]) => (
                  <div key={key} className="bg-slate-900/30 rounded px-2 py-1.5">
                    <div className="text-xs text-slate-500 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</div>
                    <div className="text-sm text-slate-200 font-medium">{value}</div>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
