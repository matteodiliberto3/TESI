import React from 'react';

interface IsometricProps {
  size?: number;
  isHovered?: boolean;
}

export const IsometricGate: React.FC<IsometricProps> = ({ size = 180, isHovered = false }) => {
  return (
    <svg
      width={size}
      height={size * 0.9}
      viewBox="0 0 200 180"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="transition-transform duration-300 drop-shadow-2xl"
    >
      <defs>
        <linearGradient id="gateTopGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#303036" />
          <stop offset="100%" stopColor="#16161b" />
        </linearGradient>
        <linearGradient id="gatePillarLeft" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#1c1c22" />
          <stop offset="100%" stopColor="#09090b" />
        </linearGradient>
        <linearGradient id="gatePillarRight" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#141418" />
          <stop offset="100%" stopColor="#050507" />
        </linearGradient>
      </defs>

      {/* Shadow */}
      <polygon points="100,165 165,130 100,95 35,130" fill="black" opacity="0.6" className="blur-sm" />

      {/* Base Platform */}
      <polygon
        points="100,120 165,85 100,50 35,85"
        fill="url(#gateTopGrad)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1.2"
      />
      <polygon
        points="35,85 100,120 100,135 35,100"
        fill="url(#gatePillarLeft)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1"
      />
      <polygon
        points="100,120 165,85 165,100 100,135"
        fill="url(#gatePillarRight)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1"
      />

      {/* Left Gateway Pylon */}
      <polygon
        points="50,75 70,64 70,25 50,36"
        fill="url(#gatePillarLeft)"
        stroke={isHovered ? "#ffffff" : "#71717a"}
        strokeWidth="1"
      />
      <polygon
        points="70,64 90,75 90,36 70,25"
        fill="url(#gatePillarRight)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1"
      />
      <polygon
        points="70,25 90,36 70,47 50,36"
        fill="#26262c"
        stroke={isHovered ? "#ffffff" : "#a1a1aa"}
        strokeWidth="1"
      />

      {/* Right Gateway Pylon */}
      <polygon
        points="110,75 130,64 130,25 110,36"
        fill="url(#gatePillarLeft)"
        stroke={isHovered ? "#ffffff" : "#71717a"}
        strokeWidth="1"
      />
      <polygon
        points="130,64 150,75 150,36 130,25"
        fill="url(#gatePillarRight)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1"
      />
      <polygon
        points="130,25 150,36 130,47 110,36"
        fill="#26262c"
        stroke={isHovered ? "#ffffff" : "#a1a1aa"}
        strokeWidth="1"
      />

      {/* Gateway Crossbar / Lintle */}
      <polygon
        points="60,25 140,25 140,35 60,35"
        fill="#1a1a20"
        stroke={isHovered ? "#ffffff" : "#71717a"}
        strokeWidth="1"
      />

      {/* Cryptographic Keyhole / Security Hexagon in Center */}
      <polygon
        points="100,50 115,58 115,74 100,82 85,74 85,58"
        fill="#09090b"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "1" : "0.7"}
        strokeWidth="1.2"
      />
      {/* Laser Verification Crosshairs */}
      <line x1="100" y1="55" x2="100" y2="77" stroke="#ffffff" strokeWidth="1" strokeOpacity="0.8" />
      <line x1="88" y1="66" x2="112" y2="66" stroke="#ffffff" strokeWidth="1" strokeOpacity="0.8" />
      <circle cx="100" cy="66" r="2.5" fill="#ffffff" />

      {/* Holographic Verification Lattice Grid */}
      <line x1="80" y1="75" x2="120" y2="75" stroke="#ffffff" strokeOpacity={isHovered ? "0.6" : "0.2"} strokeDasharray="2 2" strokeWidth="1" />
      <line x1="75" y1="85" x2="125" y2="85" stroke="#ffffff" strokeOpacity={isHovered ? "0.6" : "0.2"} strokeDasharray="2 2" strokeWidth="1" />
    </svg>
  );
};
