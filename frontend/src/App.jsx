/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import MainLayout from './layouts/MainLayout';
import Scanner from './components/Scanner';
import ToolsPage from './pages/ToolsPage';
import AboutPage from './pages/AboutPage';
import BatchScanPage from './pages/BatchScanPage';
import ShareResultPage from './pages/ShareResultPage';
import AdminDashboard from './pages/AdminDashboard';
import NotFoundPage from './pages/errors/NotFoundPage';
import ForbiddenPage from './pages/errors/ForbiddenPage';
import ServerErrorPage from './pages/errors/ServerErrorPage';

function App() {
  const { i18n } = useTranslation();
  const language = i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en';

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<MainLayout />}>
          <Route path="/" element={<Scanner />} />
          <Route path="/tools" element={<ToolsPage language={language} />} />
          <Route path="/batch" element={<BatchScanPage />} />
          <Route path="/about" element={<AboutPage language={language} />} />
          <Route path="/share/:scanId" element={<ShareResultPage />} />
          <Route path="/admin" element={<AdminDashboard />} />
          {/* 403/500: use navigate('/403') or navigate('/500') from guards / error boundary */}
          <Route path="/403" element={<ForbiddenPage />} />
          <Route path="/500" element={<ServerErrorPage />} />
          {/* Wildcard: must be last so unmatched paths show 404 inside MainLayout */}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
