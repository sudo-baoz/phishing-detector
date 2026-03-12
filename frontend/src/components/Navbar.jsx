/**
 * CyberSentinel Navbar
 * Professional Frontend Developer Implementation
 *
 * Structure:
 * - Left: Logo (CyberSentinel)
 * - Center: Main Navigation (Home, Toolbox, Batch, History, About)
 * - Right: Utility Actions (Theme, Language, GitHub, Ethics, Login)
 */
import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  Wrench,
  History,
  Menu,
  X,
  Github,
  Scale,
  Sun,
  Moon,
  LogIn,
  LayoutDashboard,
  User,
  LogOut,
  Globe,
  ArrowRight,
} from 'lucide-react';
import LanguageSwitcher from './LanguageSwitcher';
import EthicsModal from './EthicsModal';
import LoginModal from './LoginModal';
import { getTranslations } from '../constants/translations';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

const GITHUB_URL = import.meta.env.VITE_GITHUB_REPO || 'https://github.com/sudo-baoz/phishing-detector';

// ============================================
// Navigation Items Configuration
// ============================================
const NAV_ITEMS = [
  { path: '/', end: true, labelKey: 'home', icon: Shield },
  { path: '/tools', labelKey: 'tools', icon: Wrench },
  { path: '/batch', labelKey: null, label: 'Batch', icon: null },
  { path: '/history', labelKey: null, label: 'History', icon: History },
  { path: '/about', labelKey: 'about', icon: null },
];

// ============================================
// Main Component
// ============================================
export default function Navbar({ language = 'en' }) {
  // State management
  const [mobileOpen, setMobileOpen] = useState(false);
  const [ethicsOpen, setEthicsOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [avatarOpen, setAvatarOpen] = useState(false);
  const [loginError, setLoginError] = useState('');

  // Context hooks
  const { theme, setTheme } = useTheme();
  const { user, login, logout } = useAuth();
  const t = getTranslations(language).nav;

  const isDark = theme === 'dark';

  // ============================================
  // Event Handlers
  // ============================================
  const handleLoginOpen = () => {
    setLoginError('');
    setLoginOpen(true);
  };

  const handleLoginClose = () => {
    setLoginOpen(false);
    setLoginError('');
  };

  const toggleTheme = () => {
    setTheme(isDark ? 'light' : 'dark');
  };

  // ============================================
  // Styles (Tailwind CSS)
  // ============================================

  // Logo styles
  const logoStyles = `
    text-xl font-bold text-cyan-400
    hover:text-cyan-300 transition-colors
    drop-shadow-[0_0_10px_rgba(34,211,238,0.4)]
  `;

  // Center nav link - icon on top of text, centered
  const navLinkBase = `
    flex flex-col items-center justify-center
    gap-1 px-4 py-2
    text-sm font-medium
    rounded-lg
    transition-all duration-200
    text-slate-400 hover:text-slate-200 hover:bg-gray-800
  `;

  const navLinkActive = `
    flex flex-col items-center justify-center
    gap-1 px-4 py-2
    text-sm font-semibold
    rounded-lg
    transition-all duration-200
    text-cyan-400 bg-gray-800/60 border-b-2 border-cyan-400
  `;

  // Right utility button - with border as required
  const utilityButtonBase = `
    flex items-center justify-center
    gap-2 px-3 py-2
    text-sm font-medium
    rounded-md
    border border-gray-600
    bg-transparent
    text-slate-400
    hover:bg-gray-800 hover:text-slate-200
    transition-all duration-200
    shrink-0
  `;

  const iconButtonStyles = `
    flex items-center justify-center
    p-2.5
    rounded-md
    border border-gray-600
    bg-transparent
    text-slate-400
    hover:bg-gray-800 hover:text-slate-200
    transition-all duration-200
    shrink-0
  `;

  // ============================================
  // Render Helpers
  // ============================================
  const getLinkClass = ({ isActive }) =>
    isActive ? navLinkActive : navLinkBase;

  const renderNavItem = (item, index) => {
    const Icon = item.icon;
    const label = item.labelKey ? t[item.labelKey] : item.label;

    return (
      <NavLink
        key={item.path}
        to={item.path}
        end={item.end}
        className={getLinkClass}
      >
        {Icon && <Icon className="w-5 h-5" />}
        <span className="text-xs">{label}</span>
      </NavLink>
    );
  };

  // ============================================
  // Render
  // ============================================
  return (
    <>
      <nav className="h-16 w-full bg-gray-900/95 backdrop-blur-sm border-b border-gray-800 shrink-0 sticky top-0 z-50">
        <div className="h-16 max-w-7xl mx-auto px-4 flex justify-between items-center gap-4">
          {/* ============================================
              LEFT: Logo
          ============================================ */}
          <div className="shrink-0">
            <NavLink
              to="/"
              className="flex items-center gap-2"
              onClick={() => setMobileOpen(false)}
            >
              <span className={logoStyles}>
                CyberSentinel
              </span>
            </NavLink>
          </div>

          {/* ============================================
              CENTER: Main Navigation
              (Icon above text, centered)
          ============================================ */}
          <div className="hidden md:flex flex-1 justify-center items-center">
            <div className="flex items-center gap-2 lg:gap-4">
              {NAV_ITEMS.map(renderNavItem)}
            </div>
          </div>

          {/* ============================================
              RIGHT: Utility Actions
              (All buttons have border, rounded-md)
          ============================================ */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Theme Toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              className={iconButtonStyles}
              aria-label="Toggle theme"
            >
              {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>

            {/* Language Switcher */}
            <LanguageSwitcher embedded theme={theme} />

            {/* GitHub */}
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={iconButtonStyles}
              aria-label="GitHub"
            >
              <Github className="w-5 h-5" />
            </a>

            {/* Ethics Policy */}
            <button
              type="button"
              onClick={() => setEthicsOpen(true)}
              className={`${utilityButtonBase} hidden sm:flex`}
            >
              <Scale className="w-4 h-4" />
              <span>Ethics</span>
            </button>

            {/* Login / User Menu */}
            {!user ? (
              <button
                type="button"
                onClick={handleLoginOpen}
                className={`${utilityButtonBase} text-cyan-400 border-cyan-600/50 hover:border-cyan-400 hover:bg-cyan-900/20`}
              >
                <ArrowRight className="w-4 h-4" />
                <span className="hidden sm:inline">Login</span>
              </button>
            ) : (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setAvatarOpen((prev) => !prev)}
                  className={utilityButtonStyles}
                  title={user.email || user.username}
                >
                  <User className="w-4 h-4" />
                  <span className="hidden sm:inline text-sm max-w-[100px] truncate">
                    {user.email || user.username}
                  </span>
                </button>

                {/* User Dropdown */}
                {avatarOpen && (
                  <>
                    <div
                      className="fixed inset-0 z-[55]"
                      onClick={() => setAvatarOpen(false)}
                      aria-hidden
                    />
                    <div className="absolute right-0 top-full mt-2 py-2 rounded-lg shadow-xl z-50 min-w-[180px] bg-gray-900 border border-gray-700">
                      {user.role === 'admin' && (
                        <NavLink
                          to="/admin"
                          className="flex items-center gap-2 px-4 py-2 text-sm text-slate-300 hover:bg-gray-800"
                          onClick={() => setAvatarOpen(false)}
                        >
                          <LayoutDashboard className="w-4 h-4" />
                          Admin Dashboard
                        </NavLink>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          logout();
                          setAvatarOpen(false);
                        }}
                        className="flex items-center gap-2 w-full px-4 py-2 text-sm text-red-400 hover:bg-gray-800"
                      >
                        <LogOut className="w-4 h-4" />
                        Logout
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Mobile Hamburger */}
            <button
              type="button"
              onClick={() => setMobileOpen((prev) => !prev)}
              className={`md:hidden ${iconButtonStyles}`}
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </nav>

      {/* ============================================
          MOBILE MENU
      ============================================ */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-[60] md:hidden"
          style={{ top: '64px' }}
          aria-modal
          role="dialog"
        >
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
            aria-hidden
          />

          {/* Menu Content */}
          <div className="absolute left-0 right-0 top-0 bottom-0 overflow-auto p-4 bg-gray-900/98">
            <div className="flex flex-col gap-2">
              {/* Mobile Ethics */}
              <button
                type="button"
                onClick={() => {
                  setEthicsOpen(true);
                  setMobileOpen(false);
                }}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium text-slate-300 hover:bg-gray-800"
              >
                <Scale className="w-5 h-5" />
                {t.ethics}
              </button>

              {/* Mobile Nav Links */}
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const label = item.labelKey ? t[item.labelKey] : item.label;

                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.end}
                    className={getLinkClass}
                    onClick={() => setMobileOpen(false)}
                  >
                    {Icon && <Icon className="w-5 h-5" />}
                    <span>{label}</span>
                  </NavLink>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ============================================
          MODALS
      ============================================ */}
      <LoginModal
        open={loginOpen}
        onClose={handleLoginClose}
        onLogin={login}
        error={loginError}
      />

      <EthicsModal
        open={ethicsOpen}
        onClose={() => setEthicsOpen(false)}
        hideTrigger
        language={language}
      />
    </>
  );
}
