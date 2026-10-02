import React, { useEffect, useRef, useState } from 'react';
import { ShieldCheck, Ban, Clock, Users, Database, Zap, TrendingUp, TrendingDown, Activity } from 'lucide-react';
import { GatewayStats } from '../types';

interface KpiTilesProps {
  stats: GatewayStats | null;
}

function AnimatedNumber({ value, suffix = '' }: { value: number | string; suffix?: string }) {
  const [display, setDisplay] = useState('0');
  const prevRef = useRef(0);

  useEffect(() => {
    const target = typeof value === 'number' ? value : parseFloat(String(value)) || 0;
    const prev = prevRef.current;
    prevRef.current = target;
    if (target === prev) { setDisplay(String(value)); return; }
    const diff = target - prev;
    const steps = 20;
    let step = 0;
    const interval = setInterval(() => {
      step++;
      const eased = prev + diff * (1 - Math.pow(1 - step / steps, 3));
      setDisplay(Math.round(eased).toString());
      if (step >= steps) {
        setDisplay(String(value));
        clearInterval(interval);
      }
    }, 30);
    return () => clearInterval(interval);
  }, [value]);

  return <>{display}{suffix}</>;
}

const KPI_CONFIG = [
  {
    key: 'post_block_execution_rate',
    label: 'Post-Block Rate',
    sublabel: 'FR-1 Invariant Lock',
    icon: ShieldCheck,
    color: 'emerald',
    borderColor: '#D6CFC3',
    textColor: '#047857',
    iconColor: '#059669',
    dot: 'bg-emerald-600',
    pulseClass: 'pulse-green',
  },
  {
    key: 'total_intercepted',
    label: 'Total Interceptions',
    sublabel: 'Pre-execution inspected',
    icon: Zap,
    color: 'blue',
    borderColor: '#D6CFC3',
    textColor: '#1E232A',
    iconColor: '#2563EB',
    dot: 'bg-blue-600',
    pulseClass: 'pulse-green',
  },
  {
    key: 'blocked_count',
    label: 'Blocked Invocations',
    sublabel: 'Short-circuit at gateway',
    icon: Ban,
    color: 'red',
    borderColor: '#D6CFC3',
    textColor: '#B91C1C',
    iconColor: '#DC2626',
    dot: 'bg-red-600',
    pulseClass: 'pulse-red',
  },
  {
    key: 'pending_approvals_count',
    label: 'Pending Approvals',
    sublabel: 'Human cockpit review',
    icon: Clock,
    color: 'amber',
    borderColor: '#D6CFC3',
    textColor: '#B45309',
    iconColor: '#D97706',
    dot: 'bg-amber-600',
    pulseClass: 'pulse-amber',
  },
  {
    key: 'total_agents',
    label: 'Agent Mesh',
    sublabel: 'Circuit breaker active',
    icon: Users,
    color: 'purple',
    borderColor: '#D6CFC3',
    textColor: '#1E232A',
    iconColor: '#7C3AED',
    dot: 'bg-purple-600',
    pulseClass: '',
  },
  {
    key: 'ledger_height',
    label: 'Ledger Height',
    sublabel: 'RFC-8785 SHA-256',
    icon: Database,
    color: 'cyan',
    borderColor: '#D6CFC3',
    textColor: '#1E232A',
    iconColor: '#0D9488',
    dot: 'bg-teal-600',
    pulseClass: '',
  },
];

export const KpiTiles: React.FC<KpiTilesProps> = ({ stats }) => {
  const blockRate = stats ? (stats.blocked_count / Math.max(stats.total_intercepted, 1)) * 100 : 0;

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-4 anim-stagger">
      {KPI_CONFIG.map((cfg) => {
        const Icon = cfg.icon;
        const rawValue = stats ? stats[cfg.key as keyof GatewayStats] : null;
        const displayValue = rawValue !== null ? rawValue : '—';

        return (
          <div
            key={cfg.key}
            className="relative rounded-xl border p-4 overflow-hidden hover-lift cursor-default"
            style={{
              background: '#EDE8DE',
              borderColor: cfg.borderColor,
              boxShadow: '0 2px 8px rgba(100, 85, 70, 0.06)',
            }}
          >
            {/* Header row */}
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono font-semibold uppercase tracking-widest" style={{ color: '#7A6F62' }}>
                {cfg.label}
              </span>
              <div
                className="w-6 h-6 rounded-lg flex items-center justify-center border"
                style={{ background: '#E2DBD0', borderColor: '#D6CFC3' }}
              >
                <Icon className="w-3.5 h-3.5" style={{ color: cfg.iconColor }} />
              </div>
            </div>

            {/* Value */}
            <div
              className="font-mono text-2xl font-black leading-none mb-2"
              style={{ color: cfg.textColor }}
            >
              {cfg.key === 'ledger_height' && <span className="text-base opacity-60 mr-0.5">#</span>}
              {cfg.key === 'total_agents' && stats ? (
                <span>
                  <AnimatedNumber value={stats.total_agents} />
                  {stats.quarantined_agents_count > 0 && (
                    <span className="text-red-600 text-sm ml-1.5">-{stats.quarantined_agents_count}</span>
                  )}
                </span>
              ) : (
                <AnimatedNumber value={displayValue} />
              )}
            </div>

            {/* Risk mini bar for blocked */}
            {cfg.key === 'blocked_count' && stats && stats.total_intercepted > 0 && (
              <div className="mb-1.5">
                <div className="w-full h-1 rounded-full overflow-hidden" style={{ background: '#D6CFC3' }}>
                  <div
                    className="h-full bg-gradient-to-r from-red-600 to-red-500 rounded-full transition-all duration-700"
                    style={{ width: `${Math.min(blockRate, 100)}%` }}
                  />
                </div>
              </div>
            )}

            {/* Sub-label */}
            <div className="flex items-center gap-1.5 text-[9px] font-mono" style={{ color: '#8A7E70' }}>
              {cfg.dot && (
                <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} ${cfg.pulseClass}`} />
              )}
              {cfg.sublabel}
            </div>
          </div>
        );
      })}
    </div>
  );
};
