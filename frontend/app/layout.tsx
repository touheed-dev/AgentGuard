import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { Shield, Activity, Share2, AlertTriangle, FileSearch, CheckCircle2, Play } from "lucide-react";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "AgentGuard — Autonomous AI Security Gateway",
  description: "Enterprise runtime security, containment, and audit platform for autonomous AI agents.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable} dark h-full antialiased`}>
      <body className="min-h-full flex flex-col bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-white">
        <header className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div>
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                  AgentGuard
                </span>
                <span className="ml-2 text-xs font-mono px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800 text-cyan-400">
                  v0.8.0-P0
                </span>
              </div>
            </div>

            <nav className="flex items-center gap-1 sm:gap-2">
              <Link
                href="/"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                <Shield className="h-3.5 w-3.5" />
                Command Center
              </Link>
              <Link
                href="/activity"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                <Activity className="h-3.5 w-3.5" />
                Live Activity
              </Link>
              <Link
                href="/graph"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                <Share2 className="h-3.5 w-3.5" />
                Agent Graph
              </Link>
              <Link
                href="/incidents"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                Incidents
              </Link>
              <Link
                href="/approvals"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
              >
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                Approvals
              </Link>
              <Link
                href="/attack-lab"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold text-rose-300 bg-rose-950/40 border border-rose-800/60 hover:bg-rose-900/50 hover:text-rose-200 transition-colors"
              >
                <Play className="h-3.5 w-3.5 text-rose-400" />
                Attack Lab
              </Link>
            </nav>
          </div>
        </header>

        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
          {children}
        </main>

        <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500 font-mono">
          AgentGuard Security Boundary &bull; Authoritative Kernel &bull; RFC 8785 Chain &bull; Strict Fail-Closed
        </footer>
      </body>
    </html>
  );
}
