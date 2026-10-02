import React from 'react';

interface BrandLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl' | number;
  showWordmark?: boolean;
  showTagline?: boolean;
  showBadge?: boolean;
  badgeText?: string;
  theme?: 'light' | 'dark' | 'transparent';
  className?: string;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  size = 'md',
  showWordmark = true,
  showTagline = false,
  showBadge = true,
  badgeText = 'GATEWAY',
  theme = 'transparent',
  className = '',
}) => {
  const pixelSize = typeof size === 'number'
    ? size
    : size === 'sm'
    ? 28
    : size === 'md'
    ? 38
    : size === 'lg'
    ? 48
    : 64;

  return (
    <div className={`flex items-center gap-3.5 select-none ${className}`}>
      {/* ── Brand Shield Emblem ── */}
      <div
        className="relative flex items-center justify-center shrink-0 transition-transform duration-200 hover:scale-105"
        style={{
          width: pixelSize,
          height: pixelSize,
          background:
            theme === 'dark'
              ? '#181D24'
              : theme === 'light'
              ? '#FAF7F2'
              : 'transparent',
          borderRadius: theme !== 'transparent' ? '12px' : '0',
          boxShadow:
            theme === 'dark'
              ? '0 4px 16px rgba(0,0,0,0.4), inset 0 1px 1px rgba(255,255,255,0.1)'
              : theme === 'light'
              ? '0 2px 10px rgba(100,85,70,0.12), inset 0 1px 1px rgba(255,255,255,0.8)'
              : 'none',
        }}
      >
        <svg
          viewBox="0 0 120 120"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full drop-shadow-sm"
        >
          <defs>
            {/* Left shield gradient (Deep Emerald) */}
            <linearGradient id="shieldLeftFacet" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#044E3F" />
              <stop offset="45%" stopColor="#047857" />
              <stop offset="100%" stopColor="#065F46" />
            </linearGradient>

            {/* Right shield gradient (Warm Champagne / Stone) */}
            <linearGradient id="shieldRightFacet" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#E2DCD1" />
              <stop offset="50%" stopColor="#C5BBAE" />
              <stop offset="100%" stopColor="#9E9284" />
            </linearGradient>

            {/* Star core gradient (Vibrant Emerald Teal) */}
            <linearGradient id="coreStarGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#34D399" />
              <stop offset="50%" stopColor="#10B981" />
              <stop offset="100%" stopColor="#047857" />
            </linearGradient>

            {/* Obsidian Charcoal 'A' chevron */}
            <linearGradient id="chevronGrad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#2D333B" />
              <stop offset="100%" stopColor="#181D24" />
            </linearGradient>

            {/* Subtle glow filter */}
            <filter id="coreSparkGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="1.5" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Left Shield Outer Facet */}
          <path
            d="M 60 12 L 22 28 L 22 65 C 22 88 60 108 60 108 Z"
            fill="url(#shieldLeftFacet)"
          />

          {/* Right Shield Outer Facet */}
          <path
            d="M 60 12 L 98 28 L 98 65 C 98 88 60 108 60 108 Z"
            fill="url(#shieldRightFacet)"
          />

          {/* Left Shield Inner Cutout */}
          <path
            d="M 60 23 L 31 36 L 31 63 C 31 80 60 97 60 97 Z"
            fill={theme === 'dark' ? '#1E232A' : '#F5F0E8'}
          />

          {/* Right Shield Inner Cutout */}
          <path
            d="M 60 23 L 89 36 L 89 63 C 89 80 60 97 60 97 Z"
            fill={theme === 'dark' ? '#252B33' : '#EDE8DE'}
          />

          {/* The Central 'A' Chevron (Obsidian Charcoal) */}
          <path
            d="M 60 33 L 86 75 L 73 75 L 60 52 L 47 75 L 34 75 Z"
            fill={theme === 'dark' ? '#F5F0E8' : 'url(#chevronGrad)'}
          />

          {/* Central 4-Point Diamond Spark Star */}
          <path
            d="M 60 65 Q 60 74 69 74 Q 60 74 60 83 Q 60 74 51 74 Q 60 74 60 65 Z"
            fill="url(#coreStarGrad)"
            filter="url(#coreSparkGlow)"
          />
        </svg>

        {/* Live Pulse Dot */}
        <div
          className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full pulse-green"
          style={{ background: '#10B981', border: '1.5px solid #F5F0E8' }}
        />
      </div>

      {/* ── Wordmark & Subtitle Lockup ── */}
      {showWordmark && (
        <div className="flex flex-col justify-center">
          <div className="flex items-center gap-2">
            <span
              className="font-bold tracking-tight text-lg leading-none"
              style={{ fontFamily: 'Space Grotesk, sans-serif' }}
            >
              <span style={{ color: '#1E232A' }}>Agent</span>
              <span style={{ color: '#047857' }}>Guard</span>
            </span>

            {showBadge && (
              <span
                className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border tracking-wider"
                style={{
                  background: 'rgba(5,150,105,0.1)',
                  color: '#047857',
                  borderColor: 'rgba(5,150,105,0.3)',
                }}
              >
                {badgeText}
              </span>
            )}
          </div>

          {showTagline ? (
            <p
              className="text-[9px] font-mono uppercase tracking-widest mt-1 font-semibold"
              style={{ color: '#7A6F62' }}
            >
              Secure AI Agents. Real-World Impact.
            </p>
          ) : (
            <p className="text-[10px] font-mono mt-0.5" style={{ color: '#9A8F82' }}>
              Runtime Security & Integrity Gateway
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default BrandLogo;
