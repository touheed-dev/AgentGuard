import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Activity, Cpu, GitBranch, ShieldCheck, RotateCcw,
  Play, Square, Zap, Lock, Layers, Radar, Terminal, TrendingUp,
  BarChart2, Fingerprint, Gauge
} from 'lucide-react';
import { BrandLogo } from './BrandLogo';

export type DashboardTab = 'realtime-ecosystem' | 'runtime-integrity' | 'advanced-security' | 'orchestration-audit' | 'simulation-lab';

interface NavbarProps {
  activeTab: DashboardTab;
  setActiveTab: (tab: DashboardTab) => void;
  isConnected: boolean;
  ledgerHeight: number;
  isTrafficGenerating?: boolean;
  onToggleTraffic?: () => void;
  onResetDemo?: () => void;
  isResetting?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isConnected,
  ledgerHeight,
  isTrafficGenerating = false,
  onToggleTraffic,
  onResetDemo,
  isResetting = false,
}) => {
  const [time, setTime] = useState(new Date());

  // Tab scan animation state — one scan progress per tab id
  const [tabScanProgress, setTabScanProgress] = useState<Record<string, number>>({});
  const [scanningTab, setScanningTab] = useState<string | null>(null);
  const scanRefs = useRef<Record<string, ReturnType<typeof setInterval>>>({});

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // On tab click → run 0→100% scan then switch
  const handleTabClick = (id: DashboardTab) => {
    if (id === activeTab) return;
    // Cancel any in-flight scan
    if (scanRefs.current[id]) clearInterval(scanRefs.current[id]);

    setScanningTab(id);
    setTabScanProgress(prev => ({ ...prev, [id]: 0 }));

    let progress = 0;
    const tick = setInterval(() => {
      // Cubic ease-out: fast start, slows near 100%
      const remaining = 100 - progress;
      const increment = Math.max(1, remaining * 0.12 + Math.random() * 4);
      progress = Math.min(100, progress + increment);
      setTabScanProgress(prev => ({ ...prev, [id]: Math.round(progress) }));

      if (progress >= 100) {
        clearInterval(tick);
        delete scanRefs.current[id];
        setScanningTab(null);
        setTabScanProgress(prev => ({ ...prev, [id]: 0 }));
        setActiveTab(id);
      }
    }, 28);

    scanRefs.current[id] = tick;
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => { Object.values(scanRefs.current).forEach(clearInterval); };
  }, []);

  const TABS: {
    id: DashboardTab;
    label: string;
    sublabel: string;
    icon: React.ComponentType<{ className?: string }>;
    badge: string;
    badgePulse: boolean;
    badgeColor: string;
    accentColor: string;
  }[] = [
    {
      id: 'realtime-ecosystem',
      label: 'Real-time Ecosystem',
      sublabel: 'Live Agent Mesh',
      icon: Activity,
      badge: 'LIVE',
      badgePulse: true,
      badgeColor: 'bg-emerald-100 text-emerald-800 border-emerald-300',
      accentColor: '#047857',
    },
    {
      id: 'runtime-integrity',
      label: 'Runtime Integrity',
      sublabel: 'Autonomous Agent Monitor',
      icon: Shield,
      badge: 'ACTIVE',
      badgePulse: true,
      badgeColor: 'bg-emerald-100 text-emerald-800 border-emerald-300',
      accentColor: '#059669',
    },
    {
      id: 'advanced-security',
      label: 'Advanced Security',
      sublabel: 'Pipeline Deep Dive',
      icon: ShieldCheck,
      badge: '20 Stages',
      badgePulse: false,
      badgeColor: 'bg-sky-100 text-sky-800 border-sky-300',
      accentColor: '#0E7490',
    },
    {
      id: 'orchestration-audit',
      label: 'Orchestration & Audit',
      sublabel: `Ledger #${ledgerHeight}`,
      icon: GitBranch,
      badge: `#${ledgerHeight}`,
      badgePulse: false,
      badgeColor: 'bg-purple-100 text-purple-800 border-purple-300',
      accentColor: '#6D28D9',
    },
    {
      id: 'simulation-lab',
      label: 'Simulation Lab',
      sublabel: '6 Attack Scenarios',
      icon: Cpu,
      badge: '6 Scenarios',
      badgePulse: false,
      badgeColor: 'bg-amber-100 text-amber-800 border-amber-300',
      accentColor: '#B45309',
    },
  ];

  return (
    <header className="sticky top-0 z-40 w-full bg-[#F5F0E8] border-b border-[#D6CFC3] select-none shadow-[0_4px_20px_rgba(100,85,70,0.10)]">

      {/* ── Top strip ── */}
      <div className="px-6 py-2 flex items-center justify-between text-xs font-mono border-b border-[#D6CFC3] bg-[#EDE8DE]">
        <div className="flex items-center gap-4">
          {/* Live pulse indicator */}
          <div className="relative flex items-center justify-center">
            <span className="w-3 h-3 rounded-full bg-emerald-500 animate-ping absolute opacity-70" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-600 shadow-[0_0_8px_#059669]" />
          </div>
          <span className="text-[#1E232A] font-bold tracking-widest text-[11px]">
            AGENTGUARD AOC — LIVE ECOSYSTEM OPERATIONS
          </span>
          <span className="text-[#C0B8AE]">|</span>
          <span className="text-[#5C5245] font-semibold text-[11px]">DEPLOYMENT ACTIVE</span>
          {/* Waveform bars */}
          <div className="hidden md:flex items-end gap-[2px] h-4 ml-2">
            {[...Array(10)].map((_, i) => (
              <span
                key={i}
                className="waveform-bar"
                style={{ animationDelay: `${i * 0.12}s`, height: `${35 + Math.sin(i * 0.9) * 45}%` }}
              />
            ))}
          </div>
        </div>

        <div className="flex items-center gap-5">
          <div className="hidden md:flex items-center gap-1.5 text-[11px] text-[#0E7490] font-bold">
            <Zap className="w-3.5 h-3.5" />
            <span>PIPELINE: &lt;1.8ms</span>
          </div>
          <div className="flex items-center gap-2 font-semibold">
            <span className="text-[#5C5245] text-[11px]">PRD COMPLETED:</span>
            <span className="text-[#047857] bg-emerald-50 border border-emerald-300 px-3 py-0.5 rounded text-[11px] tracking-widest font-mono font-bold shadow-sm">
              [ DEPLOYED ]
            </span>
          </div>
        </div>
      </div>

      {/* ── Main Nav Header ── */}
      <div className="px-4 lg:px-6 py-2.5 flex items-center justify-between gap-3 bg-[#F5F0E8] overflow-x-auto min-w-0">
        {/* Brand */}
        <div className="flex items-center gap-3 shrink-0">
          <BrandLogo size={38} showWordmark={true} showBadge={true} badgeText="GATEWAY" theme="light" />
          <div className="hidden 2xl:block border-l border-[#D6CFC3] pl-3">
            <div className="text-[10px] text-[#0E7490] font-mono tracking-widest uppercase font-semibold">
              Zero-Trust Security Gateway
            </div>
            <div className="text-[9px] text-[#8A7E70] font-mono">
              RFC-8785 Merkle Boundary
            </div>
          </div>
        </div>

        {/* ═══ ADAPTIVE TABS — LARGE & ANIMATED ═══ */}
        <nav className="flex items-center gap-1.5 bg-[#E6E0D5] p-1.5 rounded-2xl border border-[#D2C9BB] shadow-[inset_0_2px_6px_rgba(100,85,70,0.10)] shrink-0">
          {TABS.map(({ id, label, sublabel, icon: Icon, badge, badgePulse, badgeColor, accentColor }) => {
            const isActive = activeTab === id;
            const isScanning = scanningTab === id;
            const progress = tabScanProgress[id] ?? 0;

            return (
              <button
                key={id}
                onClick={() => handleTabClick(id)}
                disabled={isScanning}
                className={`
                  relative flex flex-col items-center gap-1 px-4 sm:px-5 py-2.5 rounded-xl text-sm sm:text-base font-bold
                  transition-all duration-200 cursor-pointer overflow-hidden min-w-[145px] sm:min-w-[170px]
                  ${isActive
                    ? 'bg-[#FAF7F2] border border-[#A89E90] shadow-[0_4px_16px_rgba(100,85,70,0.20)] font-black'
                    : isScanning
                    ? 'bg-[#F0EDE8] border border-[#B8AE9F] shadow-inner'
                    : 'text-[#5C5245] hover:text-[#1E232A] hover:bg-[#EDE8DE]/90 border border-transparent hover:border-[#D6CFC3] hover:shadow-sm'
                  }
                `}
                style={isActive ? { borderColor: `${accentColor}50` } : {}}
              >
                {/* Scan progress bar overlay (0→100% during tab switch) */}
                {isScanning && (
                  <>
                    <div
                      className="absolute bottom-0 left-0 h-1 rounded-full transition-all duration-75"
                      style={{
                        width: `${progress}%`,
                        background: `linear-gradient(90deg, ${accentColor}88, ${accentColor})`,
                        boxShadow: `0 0 8px 1px ${accentColor}60`,
                      }}
                    />
                    {/* Vertical scan beam */}
                    <div
                      className="absolute top-0 bottom-0 w-0.5 pointer-events-none"
                      style={{
                        left: `${progress}%`,
                        background: `linear-gradient(180deg, transparent, ${accentColor}, transparent)`,
                        boxShadow: `0 0 6px 2px ${accentColor}50`,
                        opacity: 0.8,
                      }}
                    />
                  </>
                )}

                {/* Active bottom accent line */}
                {isActive && (
                  <div
                    className="absolute bottom-0 left-3 right-3 h-1 rounded-full"
                    style={{ background: accentColor, boxShadow: `0 0 10px 2px ${accentColor}90` }}
                  />
                )}

                {/* Tab content */}
                <div className="flex items-center gap-2 relative z-10">
                  <span style={isActive || isScanning ? { color: accentColor } : {}}>
                    <Icon
                      className={`w-4 h-4 transition-colors ${
                        isActive ? '' : isScanning ? 'animate-pulse' : 'text-[#7A6F62]'
                      }`}
                    />
                  </span>
                  <span
                    className={`text-sm sm:text-base font-extrabold leading-none ${
                      isActive ? 'text-[#1E232A]' : isScanning ? 'text-[#3D3530]' : 'text-[#5C5245]'
                    }`}
                  >
                    {isScanning ? `${progress}%` : label}
                  </span>
                </div>

                {/* Sublabel */}
                {!isScanning && (
                  <div className="text-xs font-mono font-semibold text-[#8A7E70] relative z-10 leading-none mt-0.5">
                    {sublabel}
                  </div>
                )}

                {/* Badge */}
                {!isScanning && (
                  <span
                    className={`relative z-10 text-[10px] font-mono font-black px-2 py-0.5 rounded-full border flex items-center gap-1 mt-1 shadow-xs ${badgeColor}`}
                  >
                    {badgePulse && (
                      <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" />
                    )}
                    {badge}
                  </span>
                )}

                {/* Scanning spinner */}
                {isScanning && (
                  <div className="relative z-10 flex items-center gap-1 mt-0.5">
                    <span style={{ color: accentColor }}>
                      <Gauge className="w-3 h-3 animate-spin" />
                    </span>
                    <span className="text-[9px] font-mono font-bold" style={{ color: accentColor }}>
                      {progress}%
                    </span>
                  </div>
                )}
              </button>
            );
          })}
        </nav>

        {/* Right controls */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Session badge */}
          <div className="hidden xl:inline-flex items-center gap-2 px-3 h-9 rounded-xl bg-[#EDE8DE] border border-[#D6CFC3] text-xs font-mono shadow-sm">
            <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_#10B981] shrink-0" />
            <span className="text-[#1E232A] font-semibold tracking-tight whitespace-nowrap leading-none">Gin: 995480…</span>
            <span className="text-[#0E7490] font-extrabold whitespace-nowrap leading-none">(ADC Live)</span>
          </div>

          {/* Traffic Toggle (Prominent SIMULATE button) */}
          {onToggleTraffic && (
            <button
              onClick={onToggleTraffic}
              className={`inline-flex items-center justify-center gap-2 px-4 h-9 sm:h-10 rounded-xl text-xs sm:text-sm font-mono font-extrabold transition-all cursor-pointer shadow-md select-none border shrink-0 hover:scale-[1.02] ${
                isTrafficGenerating
                  ? 'bg-amber-500 text-amber-950 border-amber-600 shadow-[0_0_12px_rgba(245,158,11,0.4)] animate-pulse'
                  : 'bg-[#047857] hover:bg-[#059669] text-[#FAF7F2] border-[#047857] shadow-[0_0_12px_rgba(4,120,87,0.3)]'
              }`}
              title={isTrafficGenerating ? 'Pause simulation traffic' : 'Generate live traffic'}
            >
              {isTrafficGenerating ? (
                <>
                  <Square className="w-3.5 h-3.5 fill-current animate-pulse shrink-0" />
                  <span className="whitespace-nowrap leading-none">SIM ACTIVE</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current shrink-0" />
                  <span className="whitespace-nowrap leading-none">SIMULATE</span>
                </>
              )}
            </button>
          )}

          {/* Reset */}
          {onResetDemo && (
            <button
              onClick={onResetDemo}
              disabled={isResetting}
              className="inline-flex items-center justify-center gap-1.5 px-3 h-9 sm:h-10 rounded-xl text-xs font-mono text-[#5C5245] hover:text-[#1E232A] bg-[#EDE8DE] hover:bg-[#FAF7F2] border border-[#D6CFC3] hover:border-[#B8AE9F] transition-colors cursor-pointer font-bold shadow-sm select-none shrink-0"
              title="Reset Gateway State"
            >
              <RotateCcw className={`w-3.5 h-3.5 shrink-0 ${isResetting ? 'animate-spin text-[#0E7490]' : ''}`} />
              <span className="hidden sm:inline whitespace-nowrap leading-none">Reset</span>
            </button>
          )}

          {/* GitHub Repo */}
          <a
            href="https://github.com/touheed-dev/AgentGuard"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-1.5 px-3 h-9 sm:h-10 rounded-xl text-xs font-mono text-[#5C5245] hover:text-[#1E232A] bg-[#EDE8DE] hover:bg-[#FAF7F2] border border-[#D6CFC3] hover:border-[#B8AE9F] transition-all cursor-pointer font-bold shadow-sm select-none shrink-0"
            title="View Repository on GitHub: touheed-dev/AgentGuard"
          >
            <svg className="w-3.5 h-3.5 fill-current shrink-0" viewBox="0 0 24 24">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
            </svg>
            <span className="hidden sm:inline whitespace-nowrap leading-none">GitHub</span>
          </a>
        </div>
      </div>

      {/* ── GLOBAL SCAN PROGRESS BAR (overall tab loading) ── */}
      {scanningTab && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#D6CFC3] overflow-hidden">
          <div
            className="h-full transition-all duration-75"
            style={{
              width: `${tabScanProgress[scanningTab] ?? 0}%`,
              background: `linear-gradient(90deg, #0E7490, #047857, #6D28D9)`,
              boxShadow: '0 0 12px 2px rgba(14,116,144,0.4)',
            }}
          />
        </div>
      )}
    </header>
  );
};
