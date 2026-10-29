export type ScenarioId = 'baseline' | 'deserialization' | 'crypto-defense' | 'safe-format';

export interface ScenarioInfo {
  id: ScenarioId;
  name: string;
}

export interface DockerSecuritySpec {
  containerName: string;
  baseImage: string;
  user: string;
  capabilities: string[];
  noNewPrivileges: boolean;
  mountedVolumes: {
    hostPath: string;
    containerPath: string;
    mode: 'ro' | 'rw';
  }[];
  keyStatus: {
    hasPrivateKey: boolean;
    hasPublicKey: boolean;
    note: string;
  };
}

export interface MLOpsNode {
  id: 'producer' | 'registry' | 'gate' | 'consumer' | 'audit';
  title: string;
  subtitle: string;
  domain: string;
  defaultPosition: { x: number; y: number };
  dockerSpec: DockerSecuritySpec;
  codeSnippet: string;
  pythonFile: string;
  description: string;
}
