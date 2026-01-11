import { useState } from 'react'

const defaultConfig = {
  registry: {
    db_path: './sentinel_registry.db',
    allow_unknown_tools: false,
    max_allowed_drift: 'Minor',
  },
  monitor: {
    gas_limit: 10000,
    max_context_bytes: 1000000,
    max_depth: 100,
    detect_cycles: true,
  },
  council: {
    min_votes_for_approval: 2,
    waluigi_threshold: 0.7,
    detect_waluigi: true,
  },
  global: {
    fail_closed: true,
    audit_logging: true,
    short_circuit: true,
  },
}

const configDescriptions = {
  registry: {
    db_path: 'Path to the SQLite database storing tool fingerprints',
    allow_unknown_tools: 'Allow tools not in registry (unsafe in production)',
    max_allowed_drift: 'Schema drift tolerance: None, Minor, or Major',
  },
  monitor: {
    gas_limit: 'Maximum gas budget per request',
    max_context_bytes: 'Maximum context size before overflow protection',
    max_depth: 'Maximum call stack depth',
    detect_cycles: 'Enable execution cycle detection',
  },
  council: {
    min_votes_for_approval: 'Minimum votes needed (out of 3 evaluators)',
    waluigi_threshold: 'Waluigi detection sensitivity (0.0-1.0)',
    detect_waluigi: 'Enable Waluigi effect detection',
  },
  global: {
    fail_closed: 'Errors result in Block instead of Allow',
    audit_logging: 'Enable detailed audit logging',
    short_circuit: 'Stop on first failure (performance)',
  },
}

export default function ConfigPanel() {
  const [config, setConfig] = useState(defaultConfig)
  const [activeSection, setActiveSection] = useState('registry')
  const [hasChanges, setHasChanges] = useState(false)

  const updateConfig = (section, key, value) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value
      }
    }))
    setHasChanges(true)
  }

  const renderValue = (section, key, value) => {
    const type = typeof value

    if (type === 'boolean') {
      return (
        <button
          onClick={() => updateConfig(section, key, !value)}
          className={`relative w-12 h-6 rounded-full transition-colors ${
            value ? 'bg-green-500' : 'bg-slate-600'
          }`}
        >
          <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
            value ? 'left-7' : 'left-1'
          }`}></span>
        </button>
      )
    }

    if (type === 'number') {
      return (
        <input
          type="number"
          value={value}
          onChange={(e) => updateConfig(section, key, parseInt(e.target.value) || 0)}
          className="w-32 px-3 py-1.5 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
        />
      )
    }

    if (key === 'max_allowed_drift') {
      return (
        <select
          value={value}
          onChange={(e) => updateConfig(section, key, e.target.value)}
          className="px-3 py-1.5 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="None">None</option>
          <option value="Minor">Minor</option>
          <option value="Major">Major</option>
        </select>
      )
    }

    return (
      <input
        type="text"
        value={value}
        onChange={(e) => updateConfig(section, key, e.target.value)}
        className="w-64 px-3 py-1.5 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm font-mono focus:outline-none focus:border-blue-500"
      />
    )
  }

  const sections = [
    { id: 'registry', label: 'Registry Guard', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { id: 'monitor', label: 'State Monitor', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
    { id: 'council', label: 'Cognitive Council', icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z' },
    { id: 'global', label: 'Global Settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
  ]

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Section Navigation */}
      <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4 h-fit">
        <h3 className="text-sm font-medium text-slate-400 mb-3 px-2">Configuration Sections</h3>
        <nav className="space-y-1">
          {sections.map(section => (
            <button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors ${
                activeSection === section.id
                  ? 'bg-blue-500/20 text-blue-400'
                  : 'text-slate-400 hover:bg-slate-700/50 hover:text-slate-200'
              }`}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={section.icon} />
              </svg>
              <span className="text-sm font-medium">{section.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Config Editor */}
      <div className="lg:col-span-3 bg-slate-800/50 rounded-xl border border-slate-700/50 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700/50 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-500/10 rounded-lg flex items-center justify-center">
              <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sections.find(s => s.id === activeSection)?.icon} />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-white">{sections.find(s => s.id === activeSection)?.label}</h2>
          </div>
          {hasChanges && (
            <div className="flex gap-2">
              <button
                onClick={() => { setConfig(defaultConfig); setHasChanges(false); }}
                className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-white transition-colors"
              >
                Reset
              </button>
              <button
                onClick={() => { setHasChanges(false); alert('Configuration saved (mock)'); }}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors"
              >
                Save Changes
              </button>
            </div>
          )}
        </div>

        <div className="p-5 space-y-4">
          {Object.entries(config[activeSection]).map(([key, value]) => (
            <div key={key} className="flex items-center justify-between p-4 bg-slate-900/30 rounded-lg">
              <div>
                <div className="text-white font-medium">{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</div>
                <div className="text-sm text-slate-500 mt-0.5">{configDescriptions[activeSection][key]}</div>
              </div>
              {renderValue(activeSection, key, value)}
            </div>
          ))}
        </div>

        {/* TOML Preview */}
        <div className="px-5 pb-5">
          <div className="bg-slate-900 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-slate-500 font-medium">sentinel.toml preview</span>
              <button className="text-xs text-blue-400 hover:text-blue-300">Copy to clipboard</button>
            </div>
            <pre className="text-sm text-slate-300 font-mono overflow-x-auto">
{`[${activeSection}]
${Object.entries(config[activeSection]).map(([k, v]) =>
  `${k} = ${typeof v === 'string' ? `"${v}"` : v}`
).join('\n')}`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
