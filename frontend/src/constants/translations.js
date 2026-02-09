/**
 * Centralized translations for Navbar, Tools, and About page.
 * Keys: 'en' | 'vi'
 */

export const translations = {
  en: {
    nav: {
      home: 'Home',
      tools: 'Toolbox',
      about: 'About',
      ethics: 'Ethics Policy',
    },
    tools: {
      title: 'Security Toolbox',
      subtitle: 'Essential utilities for your digital safety.',
      breach_title: 'Data Breach Checker',
      breach_desc:
        'Check if your email has appeared in known data leaks (Facebook, LinkedIn, etc). Powered by XposedOrNot.',
      unshorten_title: 'Link Unshortener',
      unshorten_desc:
        'Reveal the true destination of shortened URLs (bit.ly, etc.) before you click.',
      pass_title: 'Strong Password Gen',
      pass_desc: 'Generate complex, secure passwords locally in your browser.',
    },
    about: {
      title: 'About CyberSentinel',
      subtitle: 'Defending the digital frontier against phishing & fraud.',
      description:
        'CyberSentinel is an advanced AI-powered security platform designed to detect phishing URLs, analyze threat intelligence, and provide essential cybersecurity tools for everyone.',
      mission_title: 'Our Mission',
      mission_desc:
        'To make the internet safer by providing free, accessible, and high-tech security analysis tools.',
      contact_title: 'Connect with the Developer',
      github_btn: 'View on GitHub',
    },
  },
  vi: {
    nav: {
      home: 'Trang Chủ',
      tools: 'Công Cụ',
      about: 'Giới Thiệu',
      ethics: 'Chính Sách & Đạo Đức',
    },
    tools: {
      title: 'Hộp Công Cụ Bảo Mật',
      subtitle: 'Các tiện ích thiết yếu để bảo vệ an toàn số.',
      breach_title: 'Kiểm Tra Lộ Dữ Liệu',
      breach_desc:
        'Kiểm tra xem email của bạn có bị lộ trong các vụ rò rỉ dữ liệu lớn (Facebook, LinkedIn...) hay không.',
      unshorten_title: 'Giải Mã Link Rút Gọn',
      unshorten_desc:
        'Xem đích đến thực sự của các link rút gọn (bit.ly...) trước khi click để tránh lừa đảo.',
      pass_title: 'Tạo Mật Khẩu Mạnh',
      pass_desc:
        'Tạo mật khẩu ngẫu nhiên độ khó cao ngay tại trình duyệt. An toàn tuyệt đối.',
    },
    about: {
      title: 'Về CyberSentinel',
      subtitle: 'Bảo vệ biên giới số trước các mối đe dọa lừa đảo.',
      description:
        'CyberSentinel là nền tảng bảo mật tích hợp AI tiên tiến, được thiết kế để phát hiện URL lừa đảo, phân tích nguy cơ và cung cấp các công cụ an ninh mạng thiết yếu cho cộng đồng.',
      mission_title: 'Sứ Mệnh',
      mission_desc:
        'Giúp Internet trở nên an toàn hơn bằng cách cung cấp các công cụ phân tích bảo mật miễn phí và dễ tiếp cận.',
      contact_title: 'Liên Hệ Nhà Phát Triển',
      github_btn: 'Xem trên GitHub',
    },
  },
};

/** @param {string} [lang] - e.g. 'en', 'vi', 'vi-VN' */
export function getTranslations(lang) {
  const key = lang && String(lang).toLowerCase().startsWith('vi') ? 'vi' : 'en';
  return translations[key];
}
