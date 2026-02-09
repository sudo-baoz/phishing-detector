/**
 * Security Toolbox – Single-column list view with feature cards and descriptions.
 */

import BreachChecker from '../components/tools/BreachChecker';
import LinkExpander from '../components/tools/LinkExpander';
import PasswordGenerator from '../components/tools/PasswordGenerator';
import { Shield, Link2, KeyRound } from 'lucide-react';

const TOOLS = [
  {
    id: 'breach',
    icon: Shield,
    title: 'Data Breach Checker',
    description:
      'Kiểm tra xem email của bạn có bị lộ trong các vụ rò rỉ dữ liệu lớn (Facebook, LinkedIn...) hay không. Sử dụng dữ liệu thực từ XposedOrNot.',
    Component: BreachChecker,
  },
  {
    id: 'unshorten',
    icon: Link2,
    title: 'Link Unshortener',
    description:
      'Giải mã các đường link rút gọn (bit.ly, tinyurl...) để xem đích đến thực sự trước khi click. Tránh bị chuyển hướng đến web độc hại.',
    Component: LinkExpander,
  },
  {
    id: 'password',
    icon: KeyRound,
    title: 'Password Generator',
    description:
      'Tạo mật khẩu mạnh ngẫu nhiên với độ khó cao (Chữ hoa, ký tự đặc biệt) ngay tại trình duyệt. Không gửi dữ liệu về server.',
    Component: PasswordGenerator,
  },
];

function FeatureCard({ icon: Icon, title, description, children }) {
  return (
    <article className="rounded-xl border border-gray-700 bg-gray-900/50 p-6">
      <header className="mb-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
            <Icon className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-bold text-slate-200">{title}</h2>
        </div>
        <p className="text-slate-400 text-sm leading-relaxed pl-11">{description}</p>
      </header>
      <div className="pt-2 border-t border-gray-800">{children}</div>
    </article>
  );
}

export default function ToolsPage() {
  return (
    <div className="min-h-screen bg-black text-slate-200">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
        <header className="mb-8 sm:mb-10">
          <h1 className="text-3xl sm:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400 mb-2">
            Security Toolbox
          </h1>
          <p className="text-slate-400 text-base sm:text-lg">
            Essential utilities for your digital safety.
          </p>
        </header>

        <section className="flex flex-col gap-6">
          {TOOLS.map(({ id, icon, title, description, Component }) => (
            <FeatureCard key={id} icon={icon} title={title} description={description}>
              <Component />
            </FeatureCard>
          ))}
        </section>
      </div>
    </div>
  );
}
