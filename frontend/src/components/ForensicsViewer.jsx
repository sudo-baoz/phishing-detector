/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * Full-page forensics viewer: tabbed Desktop / Mobile screenshots from Vision Scanner.
 */

import { useState } from 'react';

export default function ForensicsViewer({ desktopImage, mobileImage }) {
  const [activeTab, setActiveTab] = useState('desktop');

  if (!desktopImage && !mobileImage) return null;

  return (
    <div className="bg-gray-900 p-4 rounded-xl border border-gray-700/50">
      <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
        🔍 Full-Page Forensics
      </h3>

      {/* Tabs */}
      <div className="flex space-x-2 mb-4 bg-gray-800 p-1 rounded-lg w-fit">
        <button
          type="button"
          onClick={() => setActiveTab('desktop')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
            activeTab === 'desktop'
              ? 'bg-blue-600 text-white shadow-lg'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          🖥️ Desktop View
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('mobile')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
            activeTab === 'mobile'
              ? 'bg-purple-600 text-white shadow-lg'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          📱 Mobile View
        </button>
      </div>

      {/* Image container (scrollable for long full-page screenshots) */}
      <div className="relative bg-gray-950 rounded-lg border border-gray-800 overflow-hidden">
        <div className="max-h-[600px] overflow-y-auto rounded-lg border border-gray-700">
          {activeTab === 'desktop' && desktopImage ? (
            <img
              src={desktopImage}
              alt="Full page desktop"
              className="w-full h-auto"
            />
          ) : activeTab === 'mobile' && mobileImage ? (
            <div className="bg-gray-900 py-4">
              <img
                src={mobileImage}
                alt="Full page mobile"
                className="max-w-sm mx-auto h-auto border-x border-gray-700 shadow-2xl"
              />
            </div>
          ) : (
            <div className="p-8 text-center text-gray-500">
              No image available for this device.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
