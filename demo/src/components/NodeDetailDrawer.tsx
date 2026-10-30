import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Container, Code } from 'lucide-react';
import { MLOpsNode } from '../types/mlops';
import { DockerSpecCard } from './DockerSpecCard';
import { CodeBytecodeInspector } from './CodeBytecodeInspector';

interface NodeDetailDrawerProps {
  node: MLOpsNode | null;
  onClose: () => void;
}

export const NodeDetailDrawer: React.FC<NodeDetailDrawerProps> = ({
  node,
  onClose
}) => {
  const [activeTab, setActiveTab] = useState<'docker' | 'code'>('docker');

  if (!node) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-end">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          onClick={onClose}
          className="fixed inset-0 bg-black/75 backdrop-blur-sm"
        />

        {/* Drawer panel */}
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ duration: 0.28, ease: [0.32, 0.72, 0, 1] }}
          className="relative w-full max-w-xl h-full bg-black border-l border-zinc-800 shadow-2xl z-10 flex flex-col overflow-hidden"
        >
          {/* Drawer Header */}
          <div className="p-5 border-b border-zinc-800 flex items-start justify-between bg-zinc-950">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="h-2 w-2 rounded-full bg-white" />
                <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider">
                  {node.domain}
                </span>
              </div>
              <h2 className="text-lg font-semibold text-white font-sans tracking-tight">
                {node.title}
              </h2>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                {node.subtitle}
              </p>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-400 hover:text-white transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Tab Navigation */}
          <div className="flex items-center gap-2 px-5 py-2.5 border-b border-zinc-800 bg-zinc-950 font-mono text-xs">
            <button
              onClick={() => setActiveTab('docker')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'docker'
                  ? 'bg-zinc-900 text-white border border-zinc-700'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              <Container className="h-3.5 w-3.5" />
              <span>Docker &amp; Isolamento</span>
            </button>

            <button
              onClick={() => setActiveTab('code')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'code'
                  ? 'bg-zinc-900 text-white border border-zinc-700'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              <Code className="h-3.5 w-3.5" />
              <span>Sorgente &amp; Bytecode</span>
            </button>
          </div>

          {/* Drawer Scrollable Content */}
          <div className="p-5 overflow-y-auto flex-1 space-y-5">
            {activeTab === 'docker' && (
              <div className="space-y-4">
                <DockerSpecCard spec={node.dockerSpec} />
              </div>
            )}

            {activeTab === 'code' && (
              <div className="space-y-4">
                <CodeBytecodeInspector
                  pythonCode={node.codeSnippet}
                  pythonFile={node.pythonFile}
                />
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
