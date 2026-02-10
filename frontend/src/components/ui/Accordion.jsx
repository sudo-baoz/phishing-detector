/**
 * Smooth collapsible accordion using CSS Grid transition (0 → auto height, 60fps).
 * Use grid-template-rows: 0fr (closed) / 1fr (open) + overflow-hidden for animation.
 */
import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

const Accordion = ({
  title,
  icon: Icon,
  children,
  defaultOpen = false,
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div
      className={`rounded-lg border border-slate-700 overflow-hidden bg-slate-900 ${className}`}
    >
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          {Icon && <Icon className="w-5 h-5 text-cyan-400 shrink-0" />}
          <span className="font-bold text-slate-200 uppercase text-sm tracking-wider">
            {title}
          </span>
        </div>
        <ChevronDown
          className={`w-5 h-5 text-slate-400 shrink-0 transition-transform duration-300 ease-in-out ${
            isOpen ? 'rotate-180' : ''
          }`}
        />
      </button>

      <div
        className={`grid transition-[grid-template-rows,opacity] duration-300 ease-in-out ${
          isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
        }`}
      >
        <div className="overflow-hidden">
          <div className="border-t border-slate-800 bg-slate-900/50 p-4 pt-4">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Accordion;
