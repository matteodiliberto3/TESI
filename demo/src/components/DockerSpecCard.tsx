import React from 'react';
import { Container, HardDrive, Key, Lock, CheckCircle2, XCircle } from 'lucide-react';
import { DockerSecuritySpec } from '../types/mlops';

interface DockerSpecCardProps {
  spec: DockerSecuritySpec;
}

export const DockerSpecCard: React.FC<DockerSpecCardProps> = ({ spec }) => {
  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 font-mono text-xs">
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <Container className="h-4 w-4 text-white" />
          <span className="font-semibold text-zinc-100">{spec.containerName}</span>
        </div>
        <span className="text-[11px] px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
          {spec.baseImage}
        </span>
      </div>

      <div className="space-y-3">
        {/* User & Kernel Security Flags */}
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-800/60">
            <span className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">Process User</span>
            <span className="text-zinc-200 font-medium">{spec.user}</span>
          </div>
          <div className="bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-800/60">
            <span className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">Kernel Capabilities</span>
            <span className="text-zinc-200 font-medium">{spec.capabilities[0]}</span>
          </div>
        </div>

        {/* Mounted Volumes */}
        <div className="bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-800/60">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1.5 flex items-center gap-1">
            <HardDrive className="h-3 w-3 text-zinc-400" />
            Mounted Volumes &amp; Permissions
          </span>
          <div className="space-y-1">
            {spec.mountedVolumes.map((vol, idx) => (
              <div key={idx} className="flex items-center justify-between text-[11px] py-0.5">
                <span className="text-zinc-400 truncate max-w-[220px]">{vol.containerPath}</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-zinc-800 text-zinc-300 border border-zinc-700">
                  :{vol.mode.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Cryptographic Key Isolation */}
        <div className="bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-800/60">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1.5 flex items-center gap-1">
            <Key className="h-3 w-3 text-zinc-400" />
            Key Boundary (Least Privilege)
          </span>
          <div className="space-y-1.5 text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Lock className="h-3 w-3 text-zinc-500" />
                RSA Private Key
              </span>
              {spec.keyStatus.hasPrivateKey ? (
                <span className="text-white flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="h-3 w-3" /> PRESENTE (CI/CD)
                </span>
              ) : (
                <span className="text-zinc-400 flex items-center gap-1 font-semibold">
                  <XCircle className="h-3 w-3" /> ISOLATA (ASSENTE)
                </span>
              )}
            </div>
            <p className="text-[10.5px] text-zinc-500 italic mt-1 leading-relaxed">
              {spec.keyStatus.note}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
