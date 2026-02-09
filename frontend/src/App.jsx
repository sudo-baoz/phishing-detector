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
import Scanner from './components/Scanner';
import Navbar from './components/Navbar';
import SecurityNewsTicker from './components/tools/SecurityNewsTicker';
import ToolsPage from './pages/ToolsPage';
import AboutPage from './pages/AboutPage';

function App() {
  const { i18n } = useTranslation();
  const language = i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en';

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-black">
        <Navbar language={language} />
        <SecurityNewsTicker />
        <Routes>
          <Route path="/" element={<Scanner />} />
          <Route path="/tools" element={<ToolsPage language={language} />} />
          <Route path="/about" element={<AboutPage language={language} />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
