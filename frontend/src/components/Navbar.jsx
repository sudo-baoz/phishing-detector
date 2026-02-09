/**
 * Modern Glassmorphism Navbar – Cyberpunk/Professional
 * Sticky, gradient logo, hover glow, mobile hamburger.
 */

import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Wrench, Menu, X } from 'lucide-react';

export default function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  const linkClass = ({ isActive }) =>
    `flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
      isActive
        ? 'text-cyan-400 bg-white/10 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
        : 'text-slate-300 hover:text-white hover:bg-white/10'
    }`;

  return (
    <nav className="sticky top-0 z-50 backdrop-blur-md bg-black/60 border-b border-white/10">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-14 sm:h-16">
          <NavLink to="/" className="flex items-center gap-2 shrink-0" onClick={() => setMobileOpen(false)}>
            <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.3)]">
              CyberSentinel
            </span>
          </NavLink>

          {/* Desktop links */}
          <div className="hidden md:flex items-center gap-1">
            <NavLink to="/" end className={linkClass}>
              <Shield className="w-4 h-4" />
              Scanner
            </NavLink>
            <NavLink to="/tools" className={linkClass}>
              <Wrench className="w-4 h-4" />
              Toolbox
            </NavLink>
          </div>

          {/* Mobile hamburger */}
          <button
            type="button"
            onClick={() => setMobileOpen((o) => !o)}
            className="md:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/10"
            aria-label="Toggle menu"
          >
            {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile menu */}
        {mobileOpen && (
          <div className="md:hidden py-3 border-t border-white/10 flex flex-col gap-1">
            <NavLink to="/" end className={linkClass} onClick={() => setMobileOpen(false)}>
              <Shield className="w-4 h-4" />
              Scanner
            </NavLink>
            <NavLink to="/tools" className={linkClass} onClick={() => setMobileOpen(false)}>
              <Wrench className="w-4 h-4" />
              Toolbox
            </NavLink>
          </div>
        )}
      </div>
    </nav>
  );
}
