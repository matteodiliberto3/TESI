import React from 'react';
import { motion } from 'framer-motion';
import { SCENARIOS } from '../data/mlopsArchitecture';
import { ScenarioId } from '../types/mlops';

interface HeaderProps {
  currentScenario: ScenarioId;
  onSelectScenario: (id: ScenarioId) => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentScenario,
  onSelectScenario,
}) => {
  return (
    <header className="border-b border-zinc-900 bg-black/90 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Left: Pure Minimal Title */}
        <div className="flex items-center gap-3">
          <div className="h-7 w-7 rounded-lg bg-zinc-950 border border-zinc-800 flex items-center justify-center">
            <div className="h-2 w-2 rounded-sm bg-white" />
          </div>
          <h1 className="text-sm font-medium tracking-tight text-white font-sans">
            MLOps Architecture Space
          </h1>
        </div>

        {/* Center: Scenario Switcher with Full Names (No T0, T1; No colors) */}
        <div className="flex items-center bg-zinc-950 border border-zinc-800/80 p-1 rounded-xl shadow-inner">
          {SCENARIOS.map((sc) => {
            const isSelected = sc.id === currentScenario;
            return (
              <button
                key={sc.id}
                onClick={() => onSelectScenario(sc.id)}
                className={`relative px-4 py-1.5 rounded-lg text-xs font-mono transition-colors duration-150 ${
                  isSelected ? 'text-white font-medium' : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                {isSelected && (
                  <motion.div
                    layoutId="scenario-pill"
                    transition={{
                      type: 'spring',
                      stiffness: 400,
                      damping: 30
                    }}
                    className="absolute inset-0 rounded-lg bg-zinc-900 border border-zinc-700/80 shadow-sm"
                  />
                )}
                <span className="relative z-10">{sc.name}</span>
              </button>
            );
          })}
        </div>

        {/* Right side left clean and free of badges/clutter */}
        <div className="hidden md:block text-[11px] font-mono text-zinc-600">
          Spazio Interattivo Vettoriale
        </div>
      </div>
    </header>
  );
};
