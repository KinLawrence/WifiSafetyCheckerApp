import { useState, useEffect, useCallback } from 'react'

// ─── Simulated Wi-Fi Data ──────────────────────────────────────────────
// Browsers cannot run system commands like "netsh wlan show networks".
// We simulate realistic network data so the scoring algorithm (ported
// from the Python desktop app) can be demonstrated faithfully.
const SIMULATED_NETWORKS = [
  { SSID: 'HomeNet-5G', Auth: 'WPA3-Personal', BSSID: 'AA:BB:CC:11:22:33', Signal: 95 },
  { SSID: 'OfficeSecure', Auth: 'WPA2-Enterprise', BSSID: 'DD:EE:FF:44:55:66', Signal: 82 },
  { SSID: 'CoffeeShop_WiFi', Auth: 'Open', BSSID: '11:22:33:AA:BB:CC', Signal: 68 },
  { SSID: 'Free Public WiFi', Auth: 'Open', BSSID: '44:55:66:DD:EE:FF', Signal: 54 },
  { SSID: 'Legacy_Router', Auth: 'WEP', BSSID: '77:88:99:00:11:22', Signal: 40 },
  { SSID: 'CoffeeShop_WiFi', Auth: 'Open', BSSID: 'AB:CD:EF:12:34:56', Signal: 62 },
  { SSID: 'Guest_Network', Auth: 'WPA2-Personal', BSSID: 'FE:DC:BA:98:76:54', Signal: 75 },
  { SSID: 'xfinitywifi', Auth: 'Open', BSSID: '99:88:77:66:55:44', Signal: 47 },
]

const CURRENT_SSID = 'HomeNet-5G'
const CURRENT_IP = '192.168.1.42'

// ─── Scoring Logic (matches Python app.py) ────────────────────────────
function analyzeNetworks(networks) {
  return networks.map((net) => {
    let score = 100
    const tags = []
    const ssid = net.SSID || 'Unknown SSID'
    const auth = net.Auth || 'Unknown'

    // Penalty for 'Open' networks (no password requirement)
    if (auth.toLowerCase().includes('open')) {
      score -= 50
      tags.push('open')
    }

    // Penalty for 'WEP' protocol (known to be insecure)
    if (auth.toLowerCase().includes('wep')) {
      score -= 40
      tags.push('wep')
    }

    // Penalty for generic names often used by phishing hotspots
    if (['free', 'guest', 'wifi', 'Free', 'Guest', 'WiFi', 'Wi-Fi', 'Public', 'Network', 'Public Wi-Fi', 'Public WiFi', 'Guest Wi-Fi', 'Guest WiFi', 'Free Wi-Fi', 'Free WiFi'].some((kw) => ssid.toLowerCase().includes(kw))) {
      score -= 10
      tags.push('suspicious')
    }

    // Penalty if multiple networks share the same name (potential Evil Twin)
    const dupes = networks.filter((n) => n.SSID === ssid)
    if (dupes.length > 1) {
      score -= 30
      tags.push('evil-twin')
    }

    score = Math.max(0, score)

    const isConnected = ssid === CURRENT_SSID

    return {
      ...net,
      ssid,
      auth,
      score,
      tags,
      isConnected,
      ip: isConnected ? CURRENT_IP : null,
    }
  })
}

// ─── Score color helpers ──────────────────────────────────────────────
function scoreColor(score) {
  if (score >= 80) return 'var(--accent-cyan)'
  if (score >= 50) return 'var(--accent-yellow)'
  return 'var(--accent-red)'
}

function scoreClass(score) {
  if (score >= 80) return 'safe'
  if (score >= 50) return 'warning'
  return 'danger'
}

// ─── Export helpers ───────────────────────────────────────────────────
function generateTxt(results) {
  const now = new Date().toLocaleString()
  let txt = `Wi-Fi Safety Scan Results\nDate: ${now}\n${'-'.repeat(40)}\n`
  results.forEach((r) => {
    const name = r.isConnected ? `${r.ssid} (${r.ip})` : r.ssid
    txt += `${name} → Security Score: ${r.score}/100\n`
  })
  return txt
}

function generateCsv(results) {
  let csv = 'SSID,Security Score,Scale\n'
  results.forEach((r) => {
    const name = r.isConnected ? `${r.ssid} (${r.ip})` : r.ssid
    // Escape commas inside SSID
    const escaped = name.includes(',') ? `"${name}"` : name
    csv += `${escaped},${r.score},100\n`
  })
  return csv
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ─── Score Ring Component ─────────────────────────────────────────────
function ScoreRing({ score }) {
  const r = 26
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color = scoreColor(score)

  return (
    <div className="score-ring">
      <svg width="64" height="64" viewBox="0 0 64 64">
        <circle className="score-ring-bg" cx="32" cy="32" r={r} />
        <circle
          className="score-ring-fill"
          cx="32"
          cy="32"
          r={r}
          stroke={color}
          strokeDasharray={circ}
          strokeDashoffset={offset}
        />
      </svg>
      <span className="score-ring-value" style={{ color }}>
        {score}
      </span>
    </div>
  )
}

// ─── Network Card Component ──────────────────────────────────────────
function NetworkCard({ network, index }) {
  const tagLabels = {
    open: 'Open',
    wep: 'WEP',
    suspicious: 'Suspicious Name',
    'evil-twin': 'Evil Twin',
  }

  return (
    <div
      className="network-card"
      id={`network-card-${index}`}
      style={{ animationDelay: `${index * 0.06}s` }}
    >
      <ScoreRing score={network.score} />
      <div className="network-info">
        <div className="network-ssid">
          <span className="network-ssid-name">{network.ssid}</span>
          {network.isConnected && (
            <span className="connected-badge">Connected</span>
          )}
        </div>
        <div className="network-meta">
          <span className="network-auth">{network.auth}</span>
          {network.ip && (
            <span className="network-ip">{network.ip}</span>
          )}
        </div>
      </div>
      <div className="network-tags">
        {network.tags.map((tag) => (
          <span key={tag} className={`tag tag-${tag}`}>
            {tagLabels[tag] || tag}
          </span>
        ))}
      </div>
    </div>
  )
}

// ─── Radar Scanning Animation ─────────────────────────────────────────
function RadarAnimation() {
  return (
    <div className="radar-container">
      <div className="radar">
        <div className="radar-sweep" />
        <span className="radar-dot" style={{ top: '18%', left: '55%' }} />
        <span className="radar-dot" style={{ top: '45%', left: '78%', animationDelay: '0.4s' }} />
        <span className="radar-dot" style={{ top: '70%', left: '35%', animationDelay: '0.8s' }} />
      </div>
      <span className="scan-status-text scan-pulse">Scanning nearby networks…</span>
    </div>
  )
}

// ─── Export Modal Component ───────────────────────────────────────────
function ExportModal({ results, onClose }) {
  const [format, setFormat] = useState('txt')
  const [toast, setToast] = useState(false)

  const preview = format === 'csv' ? generateCsv(results) : generateTxt(results)

  const handleDownload = () => {
    const now = new Date()
    const stamp = now.toISOString().slice(0, 19).replace(/[-:T]/g, (c) =>
      c === 'T' ? '_' : ''
    )
    if (format === 'csv') {
      downloadFile(generateCsv(results), `wifi_scan_${stamp}.csv`, 'text/csv')
    } else {
      downloadFile(generateTxt(results), `wifi_scan_${stamp}.txt`, 'text/plain')
    }
    setToast(true)
    setTimeout(() => {
      setToast(false)
      onClose()
    }, 1500)
  }

  return (
    <>
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <h2 className="modal-title">Export Results</h2>
            <button className="modal-close" onClick={onClose} id="modal-close-btn" aria-label="Close">
              ✕
            </button>
          </div>

          <div className="format-options">
            <button
              className={`format-btn ${format === 'txt' ? 'active' : ''}`}
              onClick={() => setFormat('txt')}
              id="format-txt-btn"
            >
              📄 TXT
              <span className="format-label">Plain text report</span>
            </button>
            <button
              className={`format-btn ${format === 'csv' ? 'active' : ''}`}
              onClick={() => setFormat('csv')}
              id="format-csv-btn"
            >
              📊 CSV
              <span className="format-label">Spreadsheet-ready</span>
            </button>
          </div>

          <div className="modal-preview">{preview}</div>

          <div className="modal-actions">
            <button className="btn-modal-cancel" onClick={onClose}>
              Cancel
            </button>
            <button className="btn-modal-download" onClick={handleDownload} id="download-btn">
              ⬇ Download
            </button>
          </div>
        </div>
      </div>
      {toast && <div className="toast">✓ File downloaded successfully</div>}
    </>
  )
}

// ─── Main App ─────────────────────────────────────────────────────────
export default function App() {
  // Clock
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  // Scanning state
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState(null)
  const [showExport, setShowExport] = useState(false)

  const handleScan = useCallback(() => {
    setScanning(true)
    setResults(null)
    // Simulate network scan delay (1.8s)
    setTimeout(() => {
      const analyzed = analyzeNetworks(SIMULATED_NETWORKS)
      setResults(analyzed)
      setScanning(false)
    }, 1800)
  }, [])

  // Derived stats
  const stats = results
    ? {
      total: results.length,
      safe: results.filter((r) => r.score >= 80).length,
      warning: results.filter((r) => r.score >= 50 && r.score < 80).length,
      danger: results.filter((r) => r.score < 50).length,
    }
    : null

  const formattedTime = time.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }) + '  ' + time.toLocaleTimeString('en-US', { hour12: false })

  return (
    <>
      {/* ── Header ── */}
      <header className="app-header">
        <div className="container header-inner">
          <div className="header-brand">
            <div className="header-icon">🛡️</div>
            <h1 className="header-title">Wi-Fi Safety Checker</h1>
          </div>
          <div className="header-clock" aria-live="polite">
            {formattedTime}
          </div>
        </div>
      </header>

      {/* ── Main ── */}
      <main className="app-main">
        <div className="container">
          {/* Hero */}
          <section className="hero">
            <p className="hero-subtitle">Network Security Scanner</p>
            <h2 className="hero-heading">
              Evaluate the safety of nearby Wi-Fi networks
            </h2>
            <p className="hero-description">
              Scan, score, and identify risky wireless networks. Detect open
              networks, weak encryption, suspicious SSIDs, and potential Evil
              Twin attacks.
            </p>
          </section>

          {/* Action Buttons */}
          <div className="actions-bar">
            <button
              className={`btn btn-scan ${scanning ? 'scanning' : ''}`}
              onClick={handleScan}
              disabled={scanning}
              id="scan-btn"
            >
              <span className="btn-icon">{scanning ? '📡' : '🔍'}</span>
              {scanning ? (
                <span className="scan-pulse">Scanning…</span>
              ) : (
                'Scan Networks'
              )}
            </button>
            <button
              className="btn btn-export"
              disabled={!results}
              onClick={() => setShowExport(true)}
              id="export-btn"
            >
              <span className="btn-icon">📤</span>
              Export Results
            </button>
          </div>

          {/* Scanning Animation */}
          {scanning && <RadarAnimation />}

          {/* Stats Bar */}
          {stats && !scanning && (
            <div className="stats-bar">
              <div className="stat-card">
                <div className="stat-value neutral">{stats.total}</div>
                <div className="stat-label">Networks Found</div>
              </div>
              <div className="stat-card">
                <div className="stat-value safe">{stats.safe}</div>
                <div className="stat-label">Secure</div>
              </div>
              <div className="stat-card">
                <div className="stat-value warning">{stats.warning}</div>
                <div className="stat-label">Caution</div>
              </div>
              <div className="stat-card">
                <div className="stat-value danger">{stats.danger}</div>
                <div className="stat-label">Unsafe</div>
              </div>
            </div>
          )}

          {/* Results */}
          {results && !scanning && (
            <div className="network-list">
              {results.map((net, i) => (
                <NetworkCard key={`${net.ssid}-${net.BSSID}`} network={net} index={i} />
              ))}
            </div>
          )}

          {/* Empty State */}
          {!results && !scanning && (
            <div className="empty-state">
              <div className="empty-icon">📶</div>
              <h3 className="empty-heading">No scan results yet</h3>
              <p className="empty-text">
                Click &quot;Scan Networks&quot; to discover and evaluate nearby
                Wi-Fi networks.
              </p>
            </div>
          )}
        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="app-footer">
        <div className="container">
          <p className="footer-text">
            Wi-Fi Safety Checker — React Edition
          </p>
          <p className="footer-note">
            Uses simulated network data for demonstration (browsers cannot
            access system Wi-Fi interfaces)
          </p>
        </div>
      </footer>

      {/* ── Export Modal ── */}
      {showExport && results && (
        <ExportModal results={results} onClose={() => setShowExport(false)} />
      )}
    </>
  )
}
