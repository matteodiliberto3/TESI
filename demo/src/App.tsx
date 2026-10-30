import React, { useState } from 'react';
import { MLOPS_NODES } from './data/mlopsArchitecture';
import { ScenarioId } from './types/mlops';
import { Header } from './components/Header';
import { PipelineSpace } from './components/PipelineSpace';
import { NodeDetailDrawer } from './components/NodeDetailDrawer';

export const App: React.FC = () => {
  const [currentScenario, setCurrentScenario] = useState<ScenarioId>('baseline');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const selectedNode = MLOPS_NODES.find(n => n.id === selectedNodeId) || null;

  return (
    <div className="h-screen w-screen bg-black text-white flex flex-col font-sans overflow-hidden select-none">
      {/* Minimal Header */}
      <Header
        currentScenario={currentScenario}
        onSelectScenario={(id) => setCurrentScenario(id)}
      />

      {/* Full-bleed Black Space with Draggable Semi-3D SVG Models */}
      <main className="flex-1 w-full h-full relative overflow-hidden bg-black">
        <PipelineSpace
          nodes={MLOPS_NODES}
          selectedNodeId={selectedNodeId}
          onSelectNode={(id) => setSelectedNodeId(id)}
        />
      </main>

      {/* Node Detail Drawer on Click */}
      <NodeDetailDrawer
        node={selectedNode}
        onClose={() => setSelectedNodeId(null)}
      />
    </div>
  );
};

export default App;
