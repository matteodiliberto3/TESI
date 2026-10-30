import React from 'react';

interface IsometricProps {
  size?: number;
  isHovered?: boolean;
}

export const IsometricConsumer: React.FC<IsometricProps> = ({ size = 180, isHovered = false }) => {
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
        <linearGradient id="consTopGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#2b2b31" />
          <stop offset="100%" stopColor="#131317" />
        </linearGradient>
        <linearGradient id="consLeftGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#18181d" />
          <stop offset="100%" stopColor="#08080a" />
        </linearGradient>
        <linearGradient id="consRightGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#111115" />
          <stop offset="100%" stopColor="#050507" />
        </linearGradient>
      </defs>

      {/* Shadow */}
      <polygon points="100,165 170,125 100,85 30,125" fill="black" opacity="0.6" className="blur-sm" />

      {/* Main High Tower Left Face */}
      <polygon
        points="45,65 100,95 100,165 45,135"
        fill="url(#consLeftGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />

      {/* Main High Tower Right Face */}
      <polygon
        points="100,95 155,65 155,135 100,165"
        fill="url(#consRightGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />

      {/* Main High Tower Top Face */}
      <polygon
        points="100,35 155,65 100,95 45,65"
        fill="url(#consTopGrad)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1.2"
      />

      {/* Serving Blade 1 (Upper Stack) */}
      <polygon
        points="45,85 100,115 155,85 100,55"
        fill="none"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.4" : "0.15"}
        strokeWidth="1"
      />

      {/* Serving Blade 2 (Middle Stack) */}
      <polygon
        points="45,110 100,140 155,110 100,80"
        fill="none"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.4" : "0.15"}
        strokeWidth="1"
      />

      {/* HTTP /predict Endpoint Port Array on Left Face */}
      <rect x="52" y="80" width="10" height="4" transform="matrix(0.866 0.5 0 1 0 0)" fill="#ffffff" opacity={isHovered ? "0.8" : "0.4"} />
      <rect x="52" y="95" width="10" height="4" transform="matrix(0.866 0.5 0 1 0 0)" fill="#ffffff" opacity={isHovered ? "0.8" : "0.4"} />
      <rect x="52" y="110" width="10" height="4" transform="matrix(0.866 0.5 0 1 0 0)" fill="#ffffff" opacity={isHovered ? "0.8" : "0.4"} />

      {/* Fast Network Interface Ports on Right Face */}
      <circle cx="118" cy="115" r="2.5" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />
      <circle cx="130" cy="108" r="2.5" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />
      <circle cx="142" cy="101" r="2.5" fill="#ffffff" opacity={isHovered ? "1" : "0.6"} />

      {/* Top Processing Emitter Antenna */}
      <line x1="100" y1="35" x2="100" y2="18" stroke="#ffffff" strokeWidth="1.5" />
      <circle cx="100" cy="16" r="3.5" fill="#ffffff" stroke="#27272a" strokeWidth="1" />
      {/* Radio Emitting Wave Circles */}
      <path
        d="M92,12 C96,9 104,9 108,12"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.8" : "0.3"}
        strokeWidth="1"
        fill="none"
      />
      <path
        d="M87,7 C94,3 106,3 113,7"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.8" : "0.2"}
        strokeWidth="1"
        fill="none"
      />
    </svg>
  );
};
