import React from 'react';

interface IsometricProps {
  size?: number;
  isHovered?: boolean;
}

export const IsometricRegistry: React.FC<IsometricProps> = ({ size = 180, isHovered = false }) => {
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
        <linearGradient id="regTopGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#2e2e34" />
          <stop offset="100%" stopColor="#15151a" />
        </linearGradient>
        <linearGradient id="regCylGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#121216" />
          <stop offset="50%" stopColor="#25252c" />
          <stop offset="100%" stopColor="#0d0d10" />
        </linearGradient>
      </defs>

      {/* Ground Shadow */}
      <ellipse cx="100" cy="155" rx="65" ry="24" fill="black" opacity="0.6" className="blur-sm" />

      {/* Layer 1: Bottom Storage Tier */}
      <path
        d="M35,120 C35,135 64,148 100,148 C136,148 165,135 165,120 L165,140 C165,155 136,168 100,168 C64,168 35,155 35,140 Z"
        fill="url(#regCylGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />
      <ellipse
        cx="100"
        cy="120"
        rx="65"
        ry="24"
        fill="url(#regTopGrad)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1"
      />

      {/* Layer 2: Middle Storage Tier */}
      <path
        d="M45,85 C45,98 70,110 100,110 C130,110 155,98 155,85 L155,102 C155,115 130,127 100,127 C70,127 45,115 45,102 Z"
        fill="url(#regCylGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />
      <ellipse
        cx="100"
        cy="85"
        rx="55"
        ry="20"
        fill="url(#regTopGrad)"
        stroke={isHovered ? "#ffffff" : "#52525b"}
        strokeWidth="1"
      />

      {/* Layer 3: Top Bucket Head / S3 Vault */}
      <path
        d="M55,50 C55,62 75,72 100,72 C125,72 145,62 145,50 L145,66 C145,78 125,88 100,88 C75,88 55,78 55,66 Z"
        fill="url(#regCylGrad)"
        stroke={isHovered ? "#ffffff" : "#3f3f46"}
        strokeWidth="1.2"
      />
      <ellipse
        cx="100"
        cy="50"
        rx="45"
        ry="17"
        fill="#1e1e24"
        stroke={isHovered ? "#ffffff" : "#71717a"}
        strokeWidth="1.2"
      />

      {/* Concentric Magnetic Ring Track on Top */}
      <ellipse
        cx="100"
        cy="50"
        rx="28"
        ry="10"
        fill="none"
        stroke="#ffffff"
        strokeOpacity={isHovered ? "0.8" : "0.3"}
        strokeDasharray="4 2"
        strokeWidth="1"
      />
      <circle cx="100" cy="50" r="4" fill="#ffffff" opacity={isHovered ? "1" : "0.7"} />

      {/* Vertical Data Bus Tracks */}
      <line x1="70" y1="62" x2="70" y2="135" stroke="#ffffff" strokeOpacity={isHovered ? "0.4" : "0.15"} strokeWidth="1" />
      <line x1="100" y1="72" x2="100" y2="148" stroke="#ffffff" strokeOpacity={isHovered ? "0.4" : "0.15"} strokeWidth="1" />
      <line x1="130" y1="62" x2="130" y2="135" stroke="#ffffff" strokeOpacity={isHovered ? "0.4" : "0.15"} strokeWidth="1" />

      {/* Storage Disk Status Indicators (Monochrome) */}
      <rect x="94" y="98" width="12" height="3" rx="1.5" fill="#ffffff" opacity={isHovered ? "1" : "0.5"} />
      <rect x="94" y="137" width="12" height="3" rx="1.5" fill="#ffffff" opacity={isHovered ? "1" : "0.5"} />
    </svg>
  );
};
