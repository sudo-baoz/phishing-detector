/**
 * Dumb Navbar: static flex container. Positioning handled by MainLayout (Fixed Header Wrapper).
 * No fixed, sticky, or top-0. LanguageSwitcher lives inside Right flex (no absolute).
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

  const rightActions = (
    <div className="flex items-center gap-4 shrink-0">
      <button
        type="button"
        onClick={() => setTheme(isDark ? 'light' : 'dark')}
        className={`p-2.5 rounded-lg transition-all ${isDark ? 'text-slate-400 hover:text-amber-400 hover:bg-white/10' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-200/60'}`}
        aria-label="Toggle theme"
      >
        {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
      </button>
      <LanguageSwitcher embedded theme={theme} />
      <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className={`p-2.5 rounded-lg transition-all ${isDark ? 'text-slate-400 hover:text-white hover:bg-white/10' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-200/60'}`} aria-label="GitHub">
        <Github className="w-5 h-5" />
      </a>
      <button type="button" onClick={() => setEthicsOpen(true)} className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${isDark ? 'text-slate-300 hover:text-white hover:bg-white/10' : 'text-gray-600 hover:text-gray-900 hover:bg-gray-200/60'}`}>
        <Scale className="w-4 h-4" />
        {t.ethics}
      </button>
      {!user ? (
        <button type="button" onClick={() => setLoginOpen(true)} className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${isDark ? 'text-cyan-400 border border-cyan-500/50 hover:bg-cyan-500/10' : 'text-cyan-600 border border-cyan-500/50 hover:bg-cyan-500/10'}`}>
          <LogIn className="w-4 h-4" />
          Login
        </button>
      ) : (
        <div className="relative">
          <button type="button" onClick={() => setAvatarOpen((o) => !o)} className={`flex items-center gap-2 px-3 py-2.5 rounded-lg transition-all ${isDark ? 'text-slate-300 hover:bg-white/10' : 'text-gray-700 hover:bg-gray-200/60'}`}>
            <User className="w-4 h-4 shrink-0" />
            <span className="text-sm truncate max-w-[100px]">{user.email || user.username}</span>
          </button>
          {avatarOpen && (
            <>
              <div className="fixed inset-0 z-[55]" onClick={() => setAvatarOpen(false)} aria-hidden />
              <div className={`absolute right-0 top-full mt-1 py-1 rounded-lg shadow-xl z-[100] min-w-[160px] ${isDark ? 'bg-gray-900 border border-white/10' : 'bg-white border border-gray-200'}`}>
                {user.role === 'admin' && (
                  <NavLink to="/admin" className={`flex items-center gap-2 px-4 py-2 text-sm ${isDark ? 'text-slate-300 hover:bg-white/10' : 'text-gray-700 hover:bg-gray-100'}`} onClick={() => setAvatarOpen(false)}>
                    <LayoutDashboard className="w-4 h-4" />
                    Admin Dashboard
                  </NavLink>
                )}
                <button type="button" onClick={() => { logout(); setAvatarOpen(false); }} className={`flex items-center gap-2 w-full px-4 py-2 text-sm ${isDark ? 'text-red-400 hover:bg-white/10' : 'text-red-600 hover:bg-gray-100'}`}>
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );

  return (
    <>
      <nav className="w-full shrink-0">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          {/* Layout: h-16 (64px) required – must match MainLayout header offset */}
          <div className="h-16 flex items-center justify-between relative">
            {/* Left: Logo */}
            <div className="flex-shrink-0">
              <NavLink to="/" className="flex items-center gap-2" onClick={() => setMobileOpen(false)}>
                <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.3)]">
                  CyberSentinel
                </span>
              </NavLink>
            </div>

            {/* Middle: Links (centered on desktop) */}
            <div className="hidden md:flex items-center gap-6 absolute left-1/2 -translate-x-1/2">
              <NavLink to="/" end className={linkClass}>
                <Shield className="w-4 h-4" />
                {t.home}
              </NavLink>
              <NavLink to="/tools" className={linkClass}>
                <Wrench className="w-4 h-4" />
                {t.tools}
              </NavLink>
              <NavLink to="/batch" className={linkClass}>
                Batch
              </NavLink>
              <NavLink to="/about" className={linkClass}>
                {t.about}
              </NavLink>
            </div>

            {/* Right: Actions (theme, language, github, ethics, login/avatar) */}
            <div className="hidden md:flex items-center">{rightActions}</div>

            {/* Mobile: actions + hamburger */}
            <div className="flex md:hidden items-center gap-2">
              {rightActions}
              <button type="button" onClick={() => setMobileOpen((o) => !o)} className={`p-2 rounded-lg ${isDark ? 'text-slate-400 hover:bg-white/10' : 'text-gray-500 hover:bg-gray-200/60'}`} aria-label="Toggle menu">
                {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>

          {/* Mobile menu */}
          {mobileOpen && (
            <div className={`md:hidden py-3 border-t ${isDark ? 'border-white/10' : 'border-gray-200'} flex flex-col gap-1`}>
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
          )}
        </div>
      </nav>

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
