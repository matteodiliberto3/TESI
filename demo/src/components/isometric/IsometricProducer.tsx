import React from 'react';

interface IsometricProps {
  size?: number;
  isHovered?: boolean;
}

export const IsometricProducer: React.FC<IsometricProps> = ({ size = 180, isHovered = false }) => {
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
        <linearGradient id="prodTopGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#2c2c32" />
          <stop offset="100%" stopColor="#141418" />
        </linearGradient>
        <linearGradient id="prodLeftGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#1a1a1f" />
          <stop offset="100%" stopColor="#0a0a0d" />
        </linearGradient>
        <linearGradient id="prodRightGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#121216" />
          <stop offset="100%" stopColor="#060608" />
        </linearGradient>
      </defs>

      {/* Base Shadow */}
      <polygon
        points="100,165 170,125 100,85 30,125"
        fill="black"
        opacity="0.6"
        className="blur-sm"
      />

      {/* Main Server Chassis Left Face */}
      <polygon
        points="30,85 100,125 100,165 30,125"
        fill="url(#prodLeftGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
        strokeLinejoin="round"
      />

      {/* Main Server Chassis Right Face */}
      <polygon
        points="100,125 170,85 170,125 100,165"
        fill="url(#prodRightGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
        strokeLinejoin="round"
      />

      {/* Main Server Chassis Top Face */}
      <polygon
        points="100,45 170,85 100,125 30,85"
        fill="url(#prodTopGrad)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1.2"
        strokeLinejoin="round"
      />

      {/* Top Face Architectural Grid Lines */}
      <path
        d="M53,72 L123,112 M76,59 L146,99 M123,58 L53,98 M146,71 L76,111"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.4" : "0.15"}
        strokeWidth="1"
      />

      {/* Central Chip / Core Unit (Raised Isometric Core) */}
      <polygon
        points="100,65 130,82 100,99 70,82"
        fill="#09090b"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.9" : "0.5"}
        strokeWidth="1.2"
      />
      <polygon
        points="100,60 130,77 100,94 70,77"
        fill="#222228"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.9" : "0.6"}
        strokeWidth="1"
      />
      {/* Micro-processor circuitry lines */}
      <line x1="100" y1="72" x2="100" y2="82" stroke="#ffffff" strokeWidth="1" strokeOpacity="0.7" />
      <line x1="90" y1="77" x2="110" y2="77" stroke="#ffffff" strokeWidth="1" strokeOpacity="0.7" />

      {/* Left Face Vents & Rack Rails */}
      <path
        d="M40,97 L90,126 M40,105 L90,134 M40,113 L90,142"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.35" : "0.18"}
        strokeWidth="1.2"
      />

      {/* Right Face Status Panel & Ports */}
      <circle cx="115" cy="140" r="2" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />
      <circle cx="125" cy="134" r="2" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />
      <circle cx="135" cy="128" r="2" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />
      <circle cx="145" cy="122" r="2" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />
      <line x1="110" y1="120" x2="160" y2="92" stroke="#ffffff" strokeWidth="1" strokeOpacity="0.2" />

      {/* Floating Training Epoch Indicator Wire */}
      <path
        d="M100,32 L100,45"
        stroke="#ffffff"
        strokeWidth="1.2"
        strokeDasharray="2 2"
        strokeOpacity={isHovered ? "0.8" : "0.3"}
      />
      <circle cx="100" cy="30" r="3" fill="#ffffff" opacity={isHovered ? "1" : "0.5"} />
    </svg>
  );
};
