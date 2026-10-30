import React from 'react';

interface IsometricProps {
  size?: number;
  isHovered?: boolean;
}

export const IsometricAudit: React.FC<IsometricProps> = ({ size = 180, isHovered = false }) => {
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
        <linearGradient id="auditTopGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#2c2c32" />
          <stop offset="100%" stopColor="#141418" />
        </linearGradient>
        <linearGradient id="auditLeftGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#19191e" />
          <stop offset="100%" stopColor="#09090c" />
        </linearGradient>
        <linearGradient id="auditRightGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#121216" />
          <stop offset="100%" stopColor="#060608" />
        </linearGradient>
      </defs>

      {/* Shadow */}
      <polygon points="100,165 165,130 100,95 35,130" fill="black" opacity="0.6" className="blur-sm" />

      {/* Low Base Terminal */}
      <polygon
        points="35,105 100,135 100,160 35,130"
        fill="url(#auditLeftGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />
      <polygon
        points="100,135 165,105 165,130 100,160"
        fill="url(#auditRightGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />
      <polygon
        points="100,80 165,105 100,135 35,105"
        fill="url(#auditTopGrad)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1.2"
      />

      {/* Holographic Radar / Probe Dish */}
      <ellipse
        cx="100"
        cy="60"
        rx="40"
        ry="22"
        fill="#111115"
        stroke={isHovered ? "#ffffff" : "#71717a"}
        strokeWidth="1.2"
      />
      <ellipse
        cx="100"
        cy="60"
        rx="26"
        ry="14"
        fill="none"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.8" : "0.3"}
        strokeDasharray="3 2"
        strokeWidth="1"
      />
      <ellipse
        cx="100"
        cy="60"
        rx="12"
        ry="6"
        fill="none"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.9" : "0.5"}
        strokeWidth="1"
      />

      {/* Central Probe Focal Pin */}
      <line x1="100" y1="60" x2="100" y2="35" stroke="#ffffff" strokeWidth="1.5" />
      <circle cx="100" cy="33" r="3" fill="#ffffff" />

      {/* Floating Scanning Rays */}
      <line x1="85" y1="20" x2="100" y2="33" stroke="#ffffff" strokeOpacity={isHovered ? "0.7" : "0.2"} strokeDasharray="2 2" strokeWidth="1" />
      <line x1="115" y1="20" x2="100" y2="33" stroke="#ffffff" strokeOpacity={isHovered ? "0.7" : "0.2"} strokeDasharray="2 2" strokeWidth="1" />

      {/* Forensic Log Ticker on Left Face */}
      <line x1="45" y1="118" x2="85" y2="136" stroke="#ffffff" strokeOpacity={isHovered ? "0.8" : "0.3"} strokeWidth="1" />
      <line x1="45" y1="123" x2="75" y2="137" stroke="#ffffff" strokeOpacity={isHovered ? "0.8" : "0.3"} strokeWidth="1" />
      <line x1="45" y1="128" x2="80" y2="144" stroke="#ffffff" strokeOpacity={isHovered ? "0.8" : "0.3"} strokeWidth="1" />
    </svg>
  );
};
