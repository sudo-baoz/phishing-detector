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
import Scanner from './components/Scanner';
import LanguageSwitcher from './components/LanguageSwitcher';
import Navbar from './components/Navbar';
import ToolsPage from './pages/ToolsPage';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-black">
        <LanguageSwitcher />
        <Navbar />
        <Routes>
          <Route path="/" element={<Scanner />} />
          <Route path="/tools" element={<ToolsPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
