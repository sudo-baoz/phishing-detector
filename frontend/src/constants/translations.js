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
