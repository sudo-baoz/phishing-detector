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
      threat_intel_title: 'Threat Intelligence & Data Sources',
      threat_intel_desc:
        'Our system leverages multiple enterprise-grade threat intelligence feeds and AI/ML models to deliver real-time phishing detection with minimal false positive rates.',
      threat_sources: {
        ai_ml: {
          title: 'AI/ML Services',
          items: [
            { name: 'Google Gemini', desc: 'Advanced AI chatbot & Sentinel AI assistant for contextual threat analysis' },
            { name: 'Google Generative AI', desc: 'Deep content inspection using state-of-the-art LLMs' },
          ],
        },
        threat_intel: {
          title: 'Global Threat Intelligence',
          items: [
            { name: 'Google Safe Browsing', desc: 'Enterprise-grade URL reputation database updated in real-time by Google\'s security team' },
            { name: 'PhishTank', desc: 'Community-driven phishing URL blacklist with millions of verified reports' },
            { name: 'OpenPhish', desc: 'Free phishing threat feed curated by security researchers worldwide' },
          ],
        },
        security: {
          title: 'Security & Captcha',
          items: [
            { name: 'Cloudflare Turnstile', desc: 'Bot protection & CAPTCHA alternative with privacy-first approach' },
            { name: '2Captcha / CapSolver', desc: 'Automated CAPTCHA solving for legitimate automated scanning workflows' },
          ],
        },
        network: {
          title: 'Network Intelligence',
          items: [
            { name: 'python-whois', desc: 'Domain registration & WHOIS data for age verification & registrar analysis' },
            { name: 'ipwhois', desc: 'IP geolocation & ASN lookup for threat actor attribution' },
          ],
        },
        screenshot: {
          title: 'Visual Analysis',
          items: [
            { name: 'Thum.io', desc: 'Automated URL screenshot capture for visual inspection' },
            { name: 'Playwright', desc: 'Headless browser screenshots (desktop + mobile) for rendered content analysis' },
          ],
        },
        database: {
          title: 'Data Storage',
          items: [
            { name: 'PostgreSQL/MySQL', desc: 'Production-grade relational database for scan history & analytics' },
            { name: 'SQLite', desc: 'Lightweight local development database' },
          ],
        },
      },
    },
    ethics: {
      title: 'Ethics & Safety Policy',
      trigger: 'Ethics & Safety Policy',
      acknowledge: 'Acknowledge',
      cards: [
        {
          title: 'No Unauthorized Crawling',
          text: 'We strictly adhere to robots.txt protocols. This tool performs On-Demand Analysis only. We do not engage in mass scanning or unauthorized data scraping of legitimate websites.',
        },
        {
          title: 'Anonymous & Ephemeral',
          text: 'We prioritize privacy. We employ Anonymous Logging. Personal Identifiable Information (PII) like emails, passwords, or body content is NEVER stored. Data is ephemeral and used solely for session analysis.',
        },
        {
          title: 'Passive Analysis Only',
          text: 'This is a defensive security tool. We generally DO NOT host, distribute, or share malicious source code (Phishing Kits). Detected threats are reported as metadata/hashes only to aid the security community.',
        },
      ],
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
      threat_intel_title: 'Nguồn Dữ Liệu & Tình Báo Đe Dọa',
      threat_intel_desc:
        'Hệ thống tích hợp nhiều nguồn tình báo đe dọa cấp doanh nghiệp và mô hình AI/ML để cung cấp khả năng phát hiện lừa đảo thời gian thực với tỷ lệ cảnh báo sai thấp.',
      threat_sources: {
        ai_ml: {
          title: 'Dịch Vụ AI/ML',
          items: [
            { name: 'Google Gemini', desc: 'Trợ lý AI tiên tiến & Sentinel AI để phân tích nguy cơ theo ngữ cảnh' },
            { name: 'Google Generative AI', desc: 'Kiểm tra nội dung sâu bằng các mô hình ngôn ngữ lớn (LLM)' },
          ],
        },
        threat_intel: {
          title: 'Tình Báo Đe Dọa Toàn Cầu',
          items: [
            { name: 'Google Safe Browsing', desc: 'Cơ sở dữ liệu uy tín URL cấp doanh nghiệp, cập nhật thời gian thực bởi đội ngũ bảo mật Google' },
            { name: 'PhishTank', desc: 'Danh sách đen URL lừa đảo được xác minh bởi cộng đồng với hàng triệu báo cáo' },
            { name: 'OpenPhish', desc: 'Nguồn cấp phí lừa đảo miễn phí được các chuyên gia bảo mật trên toàn thế giới quản lý' },
          ],
        },
        security: {
          title: 'Bảo Mật & Captcha',
          items: [
            { name: 'Cloudflare Turnstile', desc: 'Bảo vệ chống bot & thay thế CAPTCHA với cách tiếp cận ưu tiên quyền riêng tư' },
            { name: '2Captcha / CapSolver', desc: 'Giải captcha tự động cho các quy trình quét tự động hợp pháp' },
          ],
        },
        network: {
          title: 'Tình Báo Mạng',
          items: [
            { name: 'python-whois', desc: 'Dữ liệu đăng ký domain & WHOIS để xác minh tuổi domain & phân tích nhà đăng ký' },
            { name: 'ipwhois', desc: 'Vị trí địa lý IP & tra cứu ASN để xác định nguồn đe dọa' },
          ],
        },
        screenshot: {
          title: 'Phân Tích Hình Ảnh',
          items: [
            { name: 'Thum.io', desc: 'Chụp màn hình URL tự động để kiểm tra hình ảnh' },
            { name: 'Playwright', desc: 'Chụp màn hình trình duyệt headless (desktop + mobile) để phân tích nội dung hiển thị' },
          ],
        },
        database: {
          title: 'Lưu Trữ Dữ Liệu',
          items: [
            { name: 'PostgreSQL/MySQL', desc: 'Cơ sở dữ liệu quan hệ cấp sản xuất cho lịch sử quét & phân tích' },
            { name: 'SQLite', desc: 'Cơ sở dữ liệu nhẹ cho phát triển cục bộ' },
          ],
        },
      },
    },
    ethics: {
      title: 'Chính Sách Đạo Đức & An Toàn',
      trigger: 'Chính Sách Đạo Đức & An Toàn',
      acknowledge: 'Đã hiểu',
      cards: [
        {
          title: 'Không Thu Thập Dữ Liệu Trái Phép',
          text: 'Chúng tôi tuân thủ nghiêm ngặt robots.txt. Công cụ chỉ thực hiện phân tích theo yêu cầu. Chúng tôi không quét hàng loạt hay thu thập dữ liệu trái phép từ các trang web hợp pháp.',
        },
        {
          title: 'Ẩn Danh & Không Lưu Trữ',
          text: 'Chúng tôi ưu tiên quyền riêng tư. Dữ liệu được ghi nhận ẩn danh. Thông tin cá nhân (email, mật khẩu, nội dung) KHÔNG BAO GIỜ được lưu trữ. Dữ liệu chỉ dùng cho phiên phân tích và không được giữ lại.',
        },
        {
          title: 'Chỉ Phân Tích Thụ Động',
          text: 'Đây là công cụ bảo mật phòng thủ. Chúng tôi KHÔNG lưu trữ, phân phối hay chia sẻ mã nguồn độc hại (Phishing Kit). Các mối đe dọa chỉ được báo cáo dưới dạng metadata/hash để hỗ trợ cộng đồng bảo mật.',
        },
      ],
    },
  },
};

/** @param {string} [lang] - e.g. 'en', 'vi', 'vi-VN' */
export function getTranslations(lang) {
  const key = lang && String(lang).toLowerCase().startsWith('vi') ? 'vi' : 'en';
  return translations[key];
}
