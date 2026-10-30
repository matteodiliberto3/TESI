import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { MLOpsNode } from '../types/mlops';
import { IsometricProducer } from './isometric/IsometricProducer';
import { IsometricRegistry } from './isometric/IsometricRegistry';
import { IsometricGate } from './isometric/IsometricGate';
import { IsometricConsumer } from './isometric/IsometricConsumer';
import { IsometricAudit } from './isometric/IsometricAudit';

interface DraggableNodeProps {
  node: MLOpsNode;
  isSelected: boolean;
  onSelect: () => void;
  containerRef: React.RefObject<HTMLDivElement | null>;
}

export const DraggableNode: React.FC<DraggableNodeProps> = ({
  node,
  isSelected,
  onSelect,
  containerRef
}) => {
  const [isHovered, setIsHovered] = useState(false);

  const renderIsometricModel = () => {
    switch (node.id) {
      case 'producer':
        return <IsometricProducer size={190} isHovered={isHovered || isSelected} />;
      case 'registry':
        return <IsometricRegistry size={190} isHovered={isHovered || isSelected} />;
      case 'gate':
        return <IsometricGate size={190} isHovered={isHovered || isSelected} />;
      case 'consumer':
        return <IsometricConsumer size={190} isHovered={isHovered || isSelected} />;
      case 'audit':
        return <IsometricAudit size={190} isHovered={isHovered || isSelected} />;
    }
  };

  return (
    <motion.div
      drag
      dragConstraints={containerRef}
      dragElastic={0.08}
      dragMomentum={true}
      initial={{ x: node.defaultPosition.x, y: node.defaultPosition.y, opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.35, ease: [0.19, 1, 0.22, 1] }}
      whileHover={{ scale: 1.03 }}
      whileTap={{ scale: 0.98 }}
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
      onClick={onSelect}
      className={`absolute cursor-grab active:cursor-grabbing select-none flex flex-col items-center group z-20 ${
        isSelected ? 'z-30' : ''
      }`}
      style={{ touchAction: 'none' }}
    >
      {/* Semi-3D SVG Vector Model */}
      <div className="relative">
        {renderIsometricModel()}

        {/* Selected subtle white halo */}
        {isSelected && (
          <div className="absolute inset-0 rounded-full border border-white/40 pointer-events-none scale-105 transition-all" />
        )}
      </div>

      {/* Clean Monochrome Node Label (No Badges, No Colors) */}
      <div className="mt-1 text-center pointer-events-none">
        <h3 className={`text-xs font-mono font-medium tracking-wide transition-colors ${
          isSelected || isHovered ? 'text-white' : 'text-zinc-300'
        }`}>
          {node.title}
        </h3>
        <span className="text-[10px] text-zinc-500 font-mono block mt-0.5">
          {node.subtitle}
        </span>
      </div>
    </motion.div>
  );
};
