/**
 * Simple top navigation: Scanner | Toolbox
 * Add this to your layout and use NavLink for active state.
 */

import { NavLink } from 'react-router-dom';
import { Shield, Wrench } from 'lucide-react';

export default function AppNav() {
  return (
    <nav className="border-b border-slate-800 bg-slate-900/90 backdrop-blur-sm sticky top-0 z-20">
      <div className="max-w-6xl mx-auto px-4 flex items-center gap-1">
        <NavLink
          to="/"
          end
          className={({ isActive }) =>
            `flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
              isActive ? 'text-cyan-400 border-b-2 border-cyan-500' : 'text-slate-400 hover:text-white'
            }`
          }
        >
          <Shield className="w-4 h-4" />
          Scanner
        </NavLink>
        <NavLink
          to="/tools"
          className={({ isActive }) =>
            `flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
              isActive ? 'text-cyan-400 border-b-2 border-cyan-500' : 'text-slate-400 hover:text-white'
            }`
          }
        >
          <Wrench className="w-4 h-4" />
          Toolbox
        </NavLink>
      </div>
    </nav>
  );
}
