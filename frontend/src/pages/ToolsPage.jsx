/**
 * Security Suite - Toolbox Page
 * Grid of BreachChecker, LinkExpander, PasswordGenerator; SecurityNewsTicker at top.
 */

import BreachChecker from '../components/tools/BreachChecker';
import LinkExpander from '../components/tools/LinkExpander';
import PasswordGenerator from '../components/tools/PasswordGenerator';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import { Wrench } from 'lucide-react';

export default function ToolsPage() {
  return (
    <div className="min-h-screen bg-black text-slate-200">
      <div className="max-w-6xl mx-auto px-4 py-6 sm:py-8 space-y-6">
        <header className="flex items-center gap-3 mb-2">
          <Wrench className="w-8 h-8 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Security Toolbox</h1>
        </header>

        <section className="mb-6">
          <SecurityNewsTicker />
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          <BreachChecker />
          <LinkExpander />
          <PasswordGenerator />
        </section>
      </div>
    </div>
  );
}
