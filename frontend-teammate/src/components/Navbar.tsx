import React, { useState, useEffect } from 'react';
import { Shield, Activity, Cpu, GitBranch, History, Radio, Lock } from 'lucide-react';

interface NavbarProps {
  activeTab: 'command-center' | 'pipeline' | 'attack-lab' | 'checkpoints';
  setActiveTab: (tab: 'command-center' | 'pipeline' | 'attack-lab' | 'checkpoints') => void;
  isConnected: boolean;
  ledgerHeight: number;
  isTrafficGenerating?: boolean;
  onToggleTraffic?: () => void;
}

const TABS = [
  { id: 'command-center' as const, label: 'Command Center', icon: Activity },
  { id: 'pipeline'       as const, label: '20-Stage Pipeline', icon: Cpu },
  { id: 'attack-lab'     as const, label: 'Attack Lab',      icon: GitBranch },
  { id: 'checkpoints'    as const, label: 'Checkpoints',     icon: History },
];

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isConnected,
  ledgerHeight,
  isTrafficGenerating = false,
  onToggleTraffic,
}) => {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const tickerItems = [
    `LEDGER #${ledgerHeight}`,
    'POST-BLOCK EXEC RATE: 0.00%',
    'RFC-8785 SHA-256 CANONICAL',
    'CEL ENGINE: DETERMINISTIC',
    'FAIL-CLOSED INVARIANT: ACTIVE',
    'Ed25519 TOKEN FRESHNESS: OK',
    'STAGE-GATE KERNEL: v2.4.1',
    '20-STAGE PIPELINE: ARMED',
  ];

  return (
    <header className="sticky top-0 z-40 w-full" style={{ background: '#F5F0E8' }}>

      {/* ── Top ticker strip — warm beige ── */}
      <div
        className="px-6 py-1 flex items-center justify-between text-[10px] font-mono border-b"
        style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}
      >
        <div className="ticker-wrap flex-1 mr-8 overflow-hidden">
          <span className="inline-block anim-ticker uppercase tracking-widest whitespace-nowrap" style={{ color: '#6B7280' }}>
            {[...tickerItems, ...tickerItems].map((item, i) => (
              <span key={i} className="mr-10">
                <span className="mr-1" style={{ color: '#059669' }}>›</span>
                {item}
              </span>
            ))}
          </span>
        </div>
        <div className="flex items-center gap-4 shrink-0" style={{ color: '#9A8F82' }}>
          <span className="flex items-center gap-1">
            <Lock className="w-2.5 h-2.5" style={{ color: '#059669' }} />
            <span style={{ color: '#047857' }}>FAIL-CLOSED</span>
          </span>
          <span>{time.toLocaleTimeString('en-US', { hour12: false })}</span>
        </div>
      </div>

      {/* ── Main header — same beige as page ── */}
      <div
        className="px-6 py-3 border-b"
        style={{
          background: '#F5F0E8',
          borderColor: '#D6CFC3',
          boxShadow: '0 2px 12px 0 rgba(100,85,70,0.08)',
        }}
      >
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between gap-4">

          {/* ── Brand ── */}
          <div className="flex items-center gap-3 shrink-0">
            <div
              className="relative w-9 h-9 rounded-xl flex items-center justify-center border"
              style={{
                background: 'linear-gradient(135deg, rgba(5,150,105,0.12), rgba(5,150,105,0.04))',
                borderColor: 'rgba(5,150,105,0.35)',
                boxShadow: '0 0 14px rgba(5,150,105,0.15)',
              }}
            >
              <Shield className="w-5 h-5" style={{ color: '#059669' }} />
              <div
                className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full pulse-green"
                style={{ background: '#34d399' }}
              />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span
                  className="font-bold text-base tracking-tight"
                  style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#1E232A' }}
                >
                  AgentGuard
                </span>
                <span
                  className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border"
                  style={{
                    background: 'rgba(5,150,105,0.1)',
                    color: '#047857',
                    borderColor: 'rgba(5,150,105,0.3)',
                  }}
                >
                  v2.4.1
                </span>
              </div>
              <p className="text-[10px] font-mono" style={{ color: '#9A8F82' }}>
                Runtime Security Gateway
              </p>
            </div>
          </div>

          {/* ── Navigation Tabs — all beige tabs ── */}
          <nav
            className="flex items-center gap-1.5 rounded-xl p-1.5"
            style={{
              background: '#E6E0D5',
              border: '1px solid #D2C9BB',
              boxShadow: 'inset 0 1px 3px rgba(100,85,70,0.1)',
            }}
          >
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className="relative flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all duration-200 cursor-pointer"
                  style={
                    isActive
                      ? {
                          background: '#FAF7F2',
                          color: '#1E232A',
                          border: '1px solid #B8AE9F',
                          boxShadow: '0 2px 8px rgba(100,85,70,0.16)',
                        }
                      : {
                          background: '#ECE6DC',
                          color: '#5C5346',
                          border: '1px solid #DCD4C7',
                        }
                  }
                  onMouseEnter={(e) => {
                    if (!isActive) {
                      (e.currentTarget as HTMLButtonElement).style.background = '#F4EFE6';
                      (e.currentTarget as HTMLButtonElement).style.borderColor = '#CCC4B6';
                      (e.currentTarget as HTMLButtonElement).style.color = '#2E271F';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) {
                      (e.currentTarget as HTMLButtonElement).style.background = '#ECE6DC';
                      (e.currentTarget as HTMLButtonElement).style.borderColor = '#DCD4C7';
                      (e.currentTarget as HTMLButtonElement).style.color = '#5C5346';
                    }
                  }}
                >
                  <Icon
                    className="w-3.5 h-3.5"
                    style={{ color: isActive ? '#059669' : '#8A7E70' }}
                  />
                  <span>{tab.label}</span>
                  {isActive && (
                    <span
                      className="w-1.5 h-1.5 rounded-full pulse-green"
                      style={{ background: '#059669', marginLeft: '2px' }}
                    />
                  )}
                </button>
              );
            })}
          </nav>

          {/* ── Right Controls ── */}
          <div className="flex items-center gap-2.5 shrink-0">

            {/* Traffic Toggle */}
            {onToggleTraffic && (
              <button
                onClick={onToggleTraffic}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[11px] font-mono font-bold border transition-all duration-200"
                style={
                  isTrafficGenerating
                    ? {
                        background: 'rgba(251,191,36,0.12)',
                        borderColor: 'rgba(251,191,36,0.45)',
                        color: '#B45309',
                        boxShadow: '0 0 12px rgba(251,191,36,0.15)',
                      }
                    : {
                        background: '#EDE8DE',
                        borderColor: '#D6CFC3',
                        color: '#7A6F62',
                      }
                }
              >
                <Radio
                  className={`w-3.5 h-3.5 ${isTrafficGenerating ? 'animate-spin' : ''}`}
                  style={{ color: isTrafficGenerating ? '#B45309' : '#9A8F82' }}
                />
                {isTrafficGenerating ? 'LIVE TRAFFIC' : 'SIM TRAFFIC'}
              </button>
            )}

            {/* WS Status */}
            <div
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono border transition-all duration-300"
              style={
                isConnected
                  ? {
                      background: 'rgba(5,150,105,0.08)',
                      borderColor: 'rgba(5,150,105,0.3)',
                      color: '#047857',
                    }
                  : {
                      background: 'rgba(220,38,38,0.07)',
                      borderColor: 'rgba(220,38,38,0.25)',
                      color: '#B91C1C',
                    }
              }
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'pulse-green' : 'animate-pulse'}`}
                style={{ background: isConnected ? '#34d399' : '#f87171' }}
              />
              {isConnected ? 'WS LIVE' : 'POLLING'}
            </div>

            {/* Ledger counter */}
            <div
              className="hidden lg:flex flex-col text-right px-3 py-1.5 rounded-lg border"
              style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}
            >
              <span className="text-[9px] font-mono uppercase tracking-wider" style={{ color: '#9A8F82' }}>
                Ledger Height
              </span>
              <span className="font-mono font-bold text-xs" style={{ color: '#1E232A' }}>
                <span style={{ color: '#059669' }}>#</span>{ledgerHeight}
              </span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
