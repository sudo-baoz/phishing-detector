/**
 * Security Toolbox – Cyber Security Dashboard
 * Gradient header, dashboard cards (grid), news ticker at top.
 */

import BreachChecker from '../components/tools/BreachChecker';
import LinkExpander from '../components/tools/LinkExpander';
import PasswordGenerator from '../components/tools/PasswordGenerator';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import { Shield, Link2, KeyRound } from 'lucide-react';

function DashboardCard({ icon: Icon, title, children }) {
  return (
    <div className="w-full rounded-xl border border-gray-800 bg-gray-900/50 p-5 sm:p-6 transition-all duration-300 hover:border-blue-500/50 hover:shadow-lg hover:shadow-blue-500/10">
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
          <Icon className="w-5 h-5" />
        </div>
        <h2 className="text-lg font-bold text-slate-200">{title}</h2>
      </div>
      {children}
    </div>
  );
}

export default function ToolsPage() {
  return (
    <div className="min-h-screen bg-black text-slate-200">
      {/* News ticker – sleek bar below navbar */}
      <section className="border-b border-white/5 bg-slate-950/80">
        <SecurityNewsTicker />
      </section>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
        {/* Header */}
        <header className="mb-8 sm:mb-10">
          <h1 className="text-3xl sm:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400 mb-2">
            Security Toolbox
          </h1>
          <p className="text-slate-400 text-base sm:text-lg">
            Essential utilities for your digital safety.
          </p>
        </header>

        {/* Dashboard grid */}
        <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <DashboardCard icon={Shield} title="Data Breach Checker">
            <BreachChecker />
          </DashboardCard>
          <DashboardCard icon={Link2} title="Link Expander">
            <LinkExpander />
          </DashboardCard>
          <DashboardCard icon={KeyRound} title="Password Generator">
            <PasswordGenerator />
          </DashboardCard>
        </section>
      </div>
    </div>
  );
}
