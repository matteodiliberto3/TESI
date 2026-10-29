import React, { useState } from 'react';
import { Code, Cpu, Copy, Check } from 'lucide-react';
import { PICKLE_BYTECODE_SAMPLE } from '../data/mlopsArchitecture';

interface CodeBytecodeInspectorProps {
  pythonCode: string;
  pythonFile: string;
}

export const CodeBytecodeInspector: React.FC<CodeBytecodeInspectorProps> = ({
  pythonCode,
  pythonFile,
}) => {
  const [activeTab, setActiveTab] = useState<'python' | 'bytecode'>('python');
  const [copied, setCopied] = useState(false);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-black border border-zinc-800 rounded-xl overflow-hidden font-mono text-xs shadow-2xl">
      {/* Tab Navigation Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-zinc-950 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('python')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'python'
                ? 'bg-zinc-900 text-white border border-zinc-700'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            <Code className="h-3.5 w-3.5" />
            <span>Python Source ({pythonFile.split(' ')[0]})</span>
          </button>

          <button
            onClick={() => setActiveTab('bytecode')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'bytecode'
                ? 'bg-zinc-900 text-white border border-zinc-700'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            <span>Pickle Bytecode (pickletools)</span>
          </button>
        </div>

        <button
          onClick={() =>
            handleCopy(
              activeTab === 'python'
                ? pythonCode
                : PICKLE_BYTECODE_SAMPLE
            )
          }
          className="p-1.5 rounded hover:bg-zinc-900 text-zinc-400 hover:text-white transition-colors"
          title="Copia codice"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-white" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      </div>

      {/* Editor Body */}
      <div className="p-4 overflow-x-auto max-h-[340px] text-zinc-300 leading-relaxed font-mono">
        {activeTab === 'python' && (
          <pre className="text-[11.5px]">
            <code>{pythonCode}</code>
          </pre>
        )}

        {activeTab === 'bytecode' && (
          <div>
            <div className="mb-2 p-2 rounded bg-zinc-900/60 border border-zinc-800 text-[11px] text-zinc-400 flex items-center gap-2">
              <Cpu className="h-4 w-4 text-zinc-300 shrink-0" />
              <span>
                Disassemblato della Python Pickle Virtual Machine (PVM).
              </span>
            </div>
            <pre className="text-[11px] text-zinc-300">
              <code>{PICKLE_BYTECODE_SAMPLE}</code>
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
