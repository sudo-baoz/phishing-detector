import { useState, useRef, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { MessageCircle, X, Send, Bot, User as UserIcon } from 'lucide-react';

const ChatWidget = ({ scanResult = null }) => {
  const { t, i18n } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);

  // Initialize with translated greeting
  useEffect(() => {
    if (messages.length === 0) {
      setMessages([{
        id: 1,
        type: 'ai',
        text: t('chat.greeting'),
        timestamp: new Date()
      }]);
    }
  }, [t, messages.length]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll to bottom when new messages arrive
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Focus input when chat opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return;

    const userMessage = inputMessage.trim();
    setInputMessage('');

    // Add user message to chat
    const newUserMessage = {
      id: Date.now(),
      type: 'user',
      text: userMessage,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, newUserMessage]);

    // Show typing indicator
    setIsLoading(true);

    try {
      // Prepare context data from scanResult
      let contextData = null;
      if (scanResult) {
        contextData = {
          url: scanResult.url || scanResult.verdict?.url,
          verdict: scanResult.verdict?.verdict || (scanResult.verdict?.is_phishing ? 'PHISHING' : 'SAFE'),
          confidence_score: scanResult.verdict?.confidence_score,
          threat_type: scanResult.verdict?.threat_type,
          forensics: scanResult.forensics,
          osint: scanResult.network,
          advanced: scanResult.advanced
        };
      }

      // Get API URL from environment variable (supports production HTTPS)
      const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

      // Call Sentinel AI API with language parameter
      const response = await fetch(`${API_URL}/chat/sentinel`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: userMessage,
          language: i18n.language, // Pass current language (en/vi)
          scan_result_id: scanResult?.id || null,
          context_data: contextData
        })
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }

      const data = await response.json();

      // Add AI response to chat
      const aiMessage = {
        id: Date.now() + 1,
        type: 'ai',
        text: data.reply,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, aiMessage]);

    } catch (error) {
      console.error('Chat error:', error);

      // Add error message
      const errorMessage = {
        id: Date.now() + 1,
        type: 'ai',
        text: t('errors.chat_error'),
        timestamp: new Date(),
        isError: true
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatTime = (date) => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <>
      {/* Floating Chat Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`fixed bottom-6 right-6 z-50 w-16 h-16 rounded-full 
          bg-gradient-to-br from-cyan-500 to-purple-600 
          shadow-lg shadow-cyan-500/50 hover:shadow-cyan-500/70
          transform hover:scale-110 transition-all duration-300
          flex items-center justify-center group
          ${isOpen ? 'rotate-90' : 'animate-pulse'}
        `}
        aria-label={isOpen ? 'Close chat' : 'Open chat'}
      >
        {isOpen ? (
          <X className="w-7 h-7 text-white" />
        ) : (
          <MessageCircle className="w-7 h-7 text-white group-hover:animate-bounce" />
        )}

        {/* Online indicator dot */}
        {!isOpen && (
          <span className="absolute top-1 right-1 w-4 h-4 bg-green-500 rounded-full border-2 border-gray-900 animate-pulse" />
        )}
      </button>

      {/* Chat Window */}
      {isOpen && (
        <div className="fixed bottom-24 right-6 z-50 w-96 h-[600px] 
          bg-gray-900 border-2 border-cyan-500/50 rounded-lg
          shadow-2xl shadow-cyan-500/20 overflow-hidden
          flex flex-col
          animate-slideUp"
          style={{
            animation: 'slideUp 0.3s ease-out'
          }}
        >
          {/* Header */}
          <div className="bg-gradient-to-r from-cyan-600 to-purple-600 p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Bot className="w-8 h-8 text-white" />
                <span className="absolute -bottom-1 -right-1 w-3 h-3 bg-green-500 rounded-full border-2 border-gray-900 animate-pulse" />
              </div>
              <div>
                <h3 className="text-white font-bold text-lg">{t('chat.title')}</h3>
                <p className="text-cyan-100 text-xs">● {t('chat.status_online')}</p>
              </div>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="text-white hover:text-cyan-200 transition-colors"
              aria-label="Close chat"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Scan Context Indicator */}
          {scanResult && (
            <div className="bg-gray-800/50 border-b border-cyan-500/30 px-4 py-2">
              <div className="flex items-center gap-2 text-xs">
                <div className={`w-2 h-2 rounded-full ${scanResult.verdict?.is_phishing ? 'bg-red-500' : 'bg-green-500'
                  } animate-pulse`} />
                <span className="text-gray-400">
                  {t('chat.context_analyzing')} <span className="text-cyan-400 font-mono">
                    {scanResult.verdict?.url?.substring(0, 40)}...
                  </span>
                </span>
              </div>
            </div>
          )}

          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-900/50 
            scrollbar-thin scrollbar-thumb-cyan-500 scrollbar-track-gray-800">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'} animate-fadeIn`}
              >
                <div className={`flex gap-2 max-w-[80%] ${message.type === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                  {/* Avatar */}
                  <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center
                    ${message.type === 'user'
                      ? 'bg-gradient-to-br from-purple-500 to-pink-500'
                      : message.isError
                        ? 'bg-gradient-to-br from-red-500 to-orange-500'
                        : 'bg-gradient-to-br from-cyan-500 to-blue-500'
                    }`}
                  >
                    {message.type === 'user' ? (
                      <UserIcon className="w-5 h-5 text-white" />
                    ) : (
                      <Bot className="w-5 h-5 text-white" />
                    )}
                  </div>

                  {/* Message Bubble */}
                  <div className="flex flex-col gap-1">
                    <div className={`rounded-lg p-3 ${message.type === 'user'
                      ? 'bg-gradient-to-br from-purple-600 to-pink-600 text-white'
                      : message.isError
                        ? 'bg-gradient-to-br from-red-900/50 to-orange-900/50 text-red-200 border border-red-500/30'
                        : 'bg-gray-800 text-gray-200 border border-cyan-500/30'
                      }`}>
                      <p className="text-sm whitespace-pre-wrap break-words">{message.text}</p>
                    </div>
                    <span className={`text-xs text-gray-500 ${message.type === 'user' ? 'text-right' : 'text-left'}`}>
                      {formatTime(message.timestamp)}
                    </span>
                  </div>
                </div>
              </div>
            ))}

            {/* Typing Indicator */}
            {isLoading && (
              <div className="flex justify-start animate-fadeIn">
                <div className="flex gap-2 max-w-[80%]">
                  <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-500 
                    flex items-center justify-center">
                    <Bot className="w-5 h-5 text-white" />
                  </div>
                  <div className="bg-gray-800 border border-cyan-500/30 rounded-lg p-3">
                    <div className="flex gap-1">
                      <span className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"
                        style={{ animationDelay: '0ms' }} />
                      <span className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"
                        style={{ animationDelay: '150ms' }} />
                      <span className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"
                        style={{ animationDelay: '300ms' }} />
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="bg-gray-800 border-t border-cyan-500/30 p-4">
            <div className="flex gap-2">
              <input
                ref={inputRef}
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={t('chat.placeholder')}
                disabled={isLoading}
                className="flex-1 bg-gray-900 text-white px-4 py-3 rounded-lg
                  border border-cyan-500/30 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20
                  outline-none transition-all placeholder-gray-500
                  disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={handleSendMessage}
                disabled={!inputMessage.trim() || isLoading}
                className="bg-gradient-to-r from-cyan-600 to-purple-600 
                  hover:from-cyan-500 hover:to-purple-500
                  disabled:from-gray-700 disabled:to-gray-700 disabled:cursor-not-allowed
                  text-white px-4 py-3 rounded-lg transition-all
                  flex items-center justify-center
                  transform hover:scale-105 active:scale-95
                  disabled:transform-none disabled:opacity-50"
                aria-label="Send message"
              >
                <Send className="w-5 h-5" />
              </button>
            </div>

            {/* Helper Text */}
            <p className="text-xs text-gray-500 mt-2 text-center">
              {scanResult
                ? t('chat.context_with_scan')
                : t('chat.context_no_scan')
              }
            </p>
          </div>
        </div>
      )}

      {/* Custom CSS for animations */}
      <style>{`
        @keyframes slideUp {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes fadeIn {
          from {
            opacity: 0;
            transform: scale(0.95);
          }
          to {
            opacity: 1;
            transform: scale(1);
          }
        }

        .animate-slideUp {
          animation: slideUp 0.3s ease-out;
        }

        .animate-fadeIn {
          animation: fadeIn 0.3s ease-out;
        }

        /* Custom scrollbar */
        .scrollbar-thin::-webkit-scrollbar {
          width: 6px;
        }

        .scrollbar-thin::-webkit-scrollbar-track {
          background: #1f2937;
          border-radius: 3px;
        }

        .scrollbar-thin::-webkit-scrollbar-thumb {
          background: #06b6d4;
          border-radius: 3px;
        }

        .scrollbar-thin::-webkit-scrollbar-thumb:hover {
          background: #0891b2;
        }
      `}</style>
    </>
  );
};

export default ChatWidget;
