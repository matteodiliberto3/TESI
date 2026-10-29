import React, { useRef } from 'react';
import { MLOpsNode } from '../types/mlops';
import { DraggableNode } from './DraggableNode';
import { RotateCcw, Move } from 'lucide-react';

interface PipelineSpaceProps {
  nodes: MLOpsNode[];
  selectedNodeId: string | null;
  onSelectNode: (id: string) => void;
  onResetPositions?: () => void;
}

export const PipelineSpace: React.FC<PipelineSpaceProps> = ({
  nodes,
  selectedNodeId,
  onSelectNode,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [resetKey, setResetKey] = React.useState(0);

  const handleReset = () => {
    setResetKey(prev => prev + 1);
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[calc(100vh-65px)] bg-black overflow-hidden select-none"
    >
      {/* Subtle Monochrome Isometric Grid Floor */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none opacity-[0.06]"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <pattern id="isoGrid" width="60" height="34.64" patternUnits="userSpaceOnUse">
            <path
              d="M 60 0 L 0 34.64 M 0 0 L 60 34.64 M 30 0 L 30 34.64"
              stroke="#ffffff"
              strokeWidth="0.8"
              fill="none"
            />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#isoGrid)" />
      </svg>

      {/* Floating Instructions / Space Helper */}
      <div className="absolute top-5 left-6 z-10 flex items-center gap-4 text-xs font-mono text-zinc-500 pointer-events-none">
        <div className="flex items-center gap-1.5 bg-zinc-950/80 border border-zinc-900 px-3 py-1.5 rounded-lg">
          <Move className="h-3.5 w-3.5 text-zinc-400" />
          <span>Trascina liberamente i modelli nello spazio</span>
        </div>
      </div>

      {/* Reset Positions Control */}
      <div className="absolute top-5 right-6 z-10">
        <button
          onClick={handleReset}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-950/80 hover:bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-400 hover:text-white transition-colors"
        >
          <RotateCcw className="h-3 w-3" />
          <span>Ripristina Posizioni</span>
        </button>
      </div>

      {/* Render all Draggable Semi-3D MLOps Nodes */}
      <div key={resetKey} className="w-full h-full relative">
        {nodes.map((node) => (
          <DraggableNode
            key={node.id}
            node={node}
            isSelected={selectedNodeId === node.id}
            onSelect={() => onSelectNode(node.id)}
            containerRef={containerRef}
          />
        ))}
      </div>
    </div>
  );
};
