/**
 * Dumb Navbar: pure flexbox. No absolute on Left/Center/Right.
 * h-16 strict. Right group: flex items-center gap-3 (no absolute).
 */
import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Wrench, Menu, X, Github, Scale, Sun, Moon, LogIn, LayoutDashboard, User, LogOut } from 'lucide-react';
import LanguageSwitcher from './LanguageSwitcher';
import EthicsModal from './EthicsModal';
import { getTranslations } from '../constants/translations';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

const GITHUB_URL = import.meta.env.VITE_GITHUB_REPO || 'https://github.com/sudo-baoz/phishing-detector';

export default function Navbar({ language = 'en' }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [ethicsOpen, setEthicsOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [avatarOpen, setAvatarOpen] = useState(false);
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');
  const { theme, setTheme } = useTheme();
  const { user, login, logout } = useAuth();
  const t = getTranslations(language).nav;

  const isDark = theme === 'dark';
  const navLinkBase = isDark ? 'text-gray-200 hover:text-blue-400 hover:bg-white/10' : 'text-gray-700 hover:text-blue-600 hover:bg-gray-200/60';
  const navLinkActive = isDark ? 'text-blue-400 bg-white/10' : 'text-blue-600 bg-gray-200/80';

  const linkClass = ({ isActive }) =>
    `flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${isActive ? navLinkActive : navLinkBase}`;

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoginError('');
    try {
      await login(loginEmail, loginPassword);
      setLoginOpen(false);
      setLoginEmail('');
      setLoginPassword('');
    } catch (err) {
      const msg = err.response?.data?.detail ?? err.message ?? 'Login failed';
      setLoginError(Array.isArray(msg) ? msg.map((x) => x?.msg ?? x).join(', ') : msg);
    }
  };

  return (
    <>
      <nav className="h-16 w-full shrink-0">
        <div className="h-16 w-full max-w-7xl mx-auto px-4 flex justify-between items-center gap-4">
          {/* Left: Logo (flex item) */}
          <div className="shrink-0 min-w-0">
            <NavLink to="/" className="flex items-center gap-2" onClick={() => setMobileOpen(false)}>
              <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.3)] truncate">
                CyberSentinel
              </span>
            </NavLink>
          </div>

          {/* Center: Nav links (flex item, centered in remaining space) */}
          <div className="hidden md:flex flex-1 justify-center items-center min-w-0">
            <div className="flex items-center gap-2 lg:gap-6">
              <NavLink to="/" end className={linkClass}>
                <Shield className="w-4 h-4 shrink-0" />
                {t.home}
              </NavLink>
              <NavLink to="/tools" className={linkClass}>
                <Wrench className="w-4 h-4 shrink-0" />
                {t.tools}
              </NavLink>
              <NavLink to="/batch" className={linkClass}>
                Batch
              </NavLink>
              <NavLink to="/about" className={linkClass}>
                {t.about}
              </NavLink>
            </div>
          </div>

          {/* Right: Actions (flex item, no absolute) */}
          <div className="flex items-center gap-3 shrink-0 min-w-0">
            <button
              type="button"
              onClick={() => setTheme(isDark ? 'light' : 'dark')}
              className={`p-2.5 rounded-lg transition-all shrink-0 ${isDark ? 'text-slate-400 hover:text-amber-400 hover:bg-white/10' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-200/60'}`}
              aria-label="Toggle theme"
            >
              {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <LanguageSwitcher embedded theme={theme} />
            <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className={`p-2.5 rounded-lg transition-all shrink-0 ${isDark ? 'text-slate-400 hover:text-white hover:bg-white/10' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-200/60'}`} aria-label="GitHub">
              <Github className="w-5 h-5" />
            </a>
            <button type="button" onClick={() => setEthicsOpen(true)} className={`hidden sm:flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium shrink-0 ${isDark ? 'text-slate-300 hover:text-white hover:bg-white/10' : 'text-gray-600 hover:text-gray-900 hover:bg-gray-200/60'}`}>
              <Scale className="w-4 h-4 shrink-0" />
              {t.ethics}
            </button>
            {!user ? (
              <button type="button" onClick={() => setLoginOpen(true)} className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium shrink-0 ${isDark ? 'text-cyan-400 border border-cyan-500/50 hover:bg-cyan-500/10' : 'text-cyan-600 border border-cyan-500/50 hover:bg-cyan-500/10'}`}>
                <LogIn className="w-4 h-4 shrink-0" />
                <span className="hidden sm:inline">Login</span>
              </button>
            ) : (
              <div className="relative shrink-0">
                <button type="button" onClick={() => setAvatarOpen((o) => !o)} className={`flex items-center gap-2 px-3 py-2.5 rounded-lg transition-all ${isDark ? 'text-slate-300 hover:bg-white/10' : 'text-gray-700 hover:bg-gray-200/60'}`}>
                  <User className="w-4 h-4 shrink-0" />
                  <span className="hidden sm:inline text-sm truncate max-w-[90px]">{user.email || user.username}</span>
                </button>
                {avatarOpen && (
                  <>
                    <div className="fixed inset-0 z-[55]" onClick={() => setAvatarOpen(false)} aria-hidden />
                    <div className={`absolute right-0 top-full mt-1 py-1 rounded-lg shadow-xl z-[50] min-w-[160px] ${isDark ? 'bg-gray-900 border border-white/10' : 'bg-white border border-gray-200'}`}>
                      {user.role === 'admin' && (
                        <NavLink to="/admin" className={`flex items-center gap-2 px-4 py-2 text-sm ${isDark ? 'text-slate-300 hover:bg-white/10' : 'text-gray-700 hover:bg-gray-100'}`} onClick={() => setAvatarOpen(false)}>
                          <LayoutDashboard className="w-4 h-4" />
                          Admin Dashboard
                        </NavLink>
                      )}
                      <button type="button" onClick={() => { logout(); setAvatarOpen(false); }} className={`flex items-center gap-2 w-full px-4 py-2 text-sm text-left ${isDark ? 'text-red-400 hover:bg-white/10' : 'text-red-600 hover:bg-gray-100'}`}>
                        <LogOut className="w-4 h-4" />
                        Logout
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}
            {/* Hamburger: only on mobile, same flex row so no overlap */}
            <button
              type="button"
              onClick={() => setMobileOpen((o) => !o)}
              className={`md:hidden p-2 rounded-lg shrink-0 ${isDark ? 'text-slate-400 hover:bg-white/10' : 'text-gray-500 hover:bg-gray-200/60'}`}
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile menu: overlay below header (top-[104px]) */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-[60] md:hidden"
          style={{ top: '104px' }}
          aria-modal
          role="dialog"
        >
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
            aria-hidden
          />
          <div className={`absolute left-0 right-0 top-0 bottom-0 overflow-auto p-4 ${isDark ? 'bg-gray-900/98' : 'bg-white/98'}`} onClick={(e) => e.stopPropagation()}>
            <div className="flex flex-col gap-1 pt-2">
              <button type="button" onClick={() => setEthicsOpen(true)} className={`flex items-center gap-2 px-4 py-3 rounded-lg text-sm font-medium ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>
                <Scale className="w-4 h-4" />
                {t.ethics}
              </button>
              <NavLink to="/" end className={linkClass} onClick={() => setMobileOpen(false)}>
                <Shield className="w-4 h-4" />
                {t.home}
              </NavLink>
              <NavLink to="/tools" className={linkClass} onClick={() => setMobileOpen(false)}>
                <Wrench className="w-4 h-4" />
                {t.tools}
              </NavLink>
              <NavLink to="/batch" className={linkClass} onClick={() => setMobileOpen(false)}>
                Batch
              </NavLink>
              <NavLink to="/about" className={linkClass} onClick={() => setMobileOpen(false)}>
                {t.about}
              </NavLink>
            </div>
          </div>
        </div>
      )}

      {loginOpen && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={() => setLoginOpen(false)}>
          <div className={`w-full max-w-sm rounded-xl shadow-2xl p-6 ${isDark ? 'bg-gray-900 border border-white/10' : 'bg-white border border-gray-200'}`} onClick={(e) => e.stopPropagation()}>
            <h3 className={`text-lg font-bold mb-4 ${isDark ? 'text-white' : 'text-gray-900'}`}>Login</h3>
            <form onSubmit={handleLogin} className="space-y-4">
              <input type="email" placeholder="Email" value={loginEmail} onChange={(e) => setLoginEmail(e.target.value)} required className={`w-full px-4 py-2 rounded-lg border ${isDark ? 'bg-gray-800 border-white/20 text-white' : 'bg-gray-50 border-gray-200 text-gray-900'}`} />
              <input type="password" placeholder="Password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} required className={`w-full px-4 py-2 rounded-lg border ${isDark ? 'bg-gray-800 border-white/20 text-white' : 'bg-gray-50 border-gray-200 text-gray-900'}`} />
              {loginError && <p className="text-sm text-red-400">{loginError}</p>}
              <button type="submit" className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium">
                Sign in
              </button>
            </form>
            <p className={`mt-3 text-xs ${isDark ? 'text-slate-500' : 'text-gray-500'}`}>Demo: admin@cybersentinel.com / password123</p>
          </div>
        </div>
      )}

      <EthicsModal open={ethicsOpen} onClose={() => setEthicsOpen(false)} hideTrigger language={language} />
    </>
  );
}
