import styles from "./login.module.css";

/**
 * Animated login hero scene — cartoon thief, glowing lock, lightning zap,
 * speech bubble, ambient particles. Pure SVG + CSS keyframes; no JS runtime.
 */
export function LoginScene() {
  return (
    <svg
      className={styles.sceneSvg}
      viewBox="0 0 700 420"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="sb-glow2" cx="35%" cy="55%" r="40%">
          <stop offset="0%" stopColor="#00f5c4" stopOpacity="0.12" />
          <stop offset="100%" stopColor="#00f5c4" stopOpacity="0" />
        </radialGradient>
        <filter id="sb-glow3">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="sb-sg3">
          <feGaussianBlur stdDeviation="7" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <circle cx="180" cy="230" r="130" fill="url(#sb-glow2)" />

      {/* Ground */}
      <ellipse cx="350" cy="385" rx="280" ry="14" fill="#000" opacity="0.25" />
      <line x1="40" y1="380" x2="660" y2="380" stroke="#1e1e2e" strokeWidth="1.5" />

      {/* White flash */}
      <rect className={styles.whiteFlashEl} width="700" height="420" fill="white" />

      {/* ═══ LOCK ═══ */}
      <g className={styles.lockGrp}>
        <circle cx="175" cy="245" r="90" fill="rgba(0,245,196,0.04)" stroke="rgba(0,245,196,0.1)" strokeWidth="1" />
        <circle cx="175" cy="245" r="70" fill="rgba(0,245,196,0.05)" stroke="rgba(0,245,196,0.07)" strokeWidth="0.8" />
        <rect x="134" y="232" width="82" height="68" rx="16" fill="#0d1a1a" stroke="#00f5c4" strokeWidth="3.5" />
        <rect x="139" y="237" width="72" height="58" rx="13" fill="none" stroke="rgba(0,245,196,0.18)" strokeWidth="1" />
        <path
          d="M152 232 L152 202 Q152 178 175 178 Q198 178 198 202 L198 232"
          stroke="#00f5c4"
          strokeWidth="8"
          fill="none"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M152 232 L152 202 Q152 178 175 178 Q198 178 198 202 L198 232"
          stroke="rgba(0,245,196,0.25)"
          strokeWidth="3.5"
          fill="none"
          strokeLinecap="round"
        />
        <circle cx="175" cy="260" r="11" fill="#00f5c4" opacity="0.9" filter="url(#sb-glow3)" />
        <rect x="171.5" y="260" width="7" height="16" rx="2.5" fill="#00f5c4" opacity="0.9" />
        <circle cx="175" cy="260" r="6" fill="#050d0d" />
        <rect x="173" y="260" width="4" height="9" rx="1" fill="#050d0d" />
        <ellipse cx="175" cy="380" rx="52" ry="8" fill="#000" opacity="0.35" />
        <text
          x="175"
          y="316"
          textAnchor="middle"
          fontFamily="'DM Mono',monospace"
          fontSize="9"
          fill="#00f5c4"
          opacity="0.5"
          letterSpacing="3"
        >
          SECURED
        </text>
      </g>

      {/* ═══ SPEECH BUBBLE ═══ */}
      <g className={styles.bubbleGrp}>
        <path
          d="M72 38 Q72 16 96 16 L278 16 Q302 16 302 38 L302 76 Q302 98 278 98 L212 98 L200 118 L192 98 L96 98 Q72 98 72 76 Z"
          fill="#00f5c4"
        />
        <text
          x="187"
          y="50"
          textAnchor="middle"
          fontFamily="Nunito,sans-serif"
          fontWeight="900"
          fontSize="12"
          fill="#051510"
        >
          THREAT DETECTED. ACCESS DENIED.
        </text>
        <text
          x="187"
          y="68"
          textAnchor="middle"
          fontFamily="Nunito,sans-serif"
          fontWeight="800"
          fontSize="14"
          fill="#061a12"
        >
          WE CATCH WHAT OTHERS MISS.
        </text>
        <text
          x="187"
          y="84"
          textAnchor="middle"
          fontFamily="'DM Mono',monospace"
          fontSize="8"
          fill="#1a4a3a"
          letterSpacing="1"
        >
          SECURITY BUDDY — ALWAYS ON GUARD
        </text>
      </g>

      {/* ═══ ZAP ═══ */}
      <g className={styles.zapGrp} filter="url(#sb-sg3)">
        <circle
          className={styles.zapRingEl}
          cx="240"
          cy="228"
          r="10"
          fill="none"
          stroke="#ffff00"
          strokeWidth="2.5"
          opacity="0.8"
        />
        <path
          d="M226 200 L248 224 L234 227 L256 256 L228 228 L244 225 Z"
          fill="#fff176"
          stroke="#ffb830"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
        <path
          d="M246 206 L262 224 L252 225 L266 242 L248 226 L256 225 Z"
          fill="#ffe082"
          stroke="#ffb830"
          strokeWidth="1"
          strokeLinejoin="round"
          opacity="0.8"
        />
        <circle cx="220" cy="210" r="4" fill="#fff" opacity="0.9" />
        <circle cx="262" cy="215" r="3" fill="#ffb830" opacity="0.9" />
        <circle cx="255" cy="260" r="2.5" fill="#fff" opacity="0.7" />
        <ellipse cx="244" cy="230" rx="18" ry="22" fill="white" opacity="0.2" />
      </g>

      {/* Electric arcs */}
      <path
        className={styles.arc1}
        d="M214 227 Q222 219 230 227 Q222 234 214 227"
        stroke="#ffff00"
        strokeWidth="2"
        fill="none"
      />
      <path
        className={styles.arc2}
        d="M252 212 Q262 207 268 215 Q260 221 252 212"
        stroke="#fff"
        strokeWidth="1.5"
        fill="none"
      />
      <path
        className={styles.arc3}
        d="M218 246 Q226 240 232 248 Q225 253 218 246"
        stroke="#ffb830"
        strokeWidth="1.5"
        fill="none"
      />

      {/* Impact stars */}
      <g className={styles.starA} style={{ transformOrigin: "222px 204px" }}>
        <text x="222" y="204" fontSize="20" fill="#ffb830" textAnchor="middle">
          ✦
        </text>
      </g>
      <g className={styles.starB} style={{ transformOrigin: "266px 202px" }}>
        <text x="266" y="202" fontSize="15" fill="#fff176" textAnchor="middle">
          ★
        </text>
      </g>
      <g className={styles.starC} style={{ transformOrigin: "256px 265px" }}>
        <text x="256" y="265" fontSize="13" fill="#fff" textAnchor="middle">
          ✦
        </text>
      </g>

      {/* ═══ THIEF ═══ */}
      <g className={styles.thiefMove}>
        <g className={styles.thiefBodyG}>
          <ellipse cx="410" cy="382" rx="52" ry="9" fill="#000" opacity="0.3" />

          {/* Legs */}
          <path
            d="M392 338 Q388 356 382 370 Q378 382 384 385 Q394 387 397 373 Q399 358 399 343Z"
            fill="#1a1a2a"
            stroke="#2d2d4e"
            strokeWidth="2"
            strokeLinejoin="round"
          />
          <path
            d="M420 338 Q426 356 432 368 Q438 382 430 385 Q420 388 418 373 Q416 358 416 343Z"
            fill="#1a1a2a"
            stroke="#2d2d4e"
            strokeWidth="2"
            strokeLinejoin="round"
          />
          <ellipse cx="384" cy="386" rx="18" ry="8" fill="#0d0d1a" stroke="#2d2d4e" strokeWidth="2" />
          <ellipse cx="426" cy="386" rx="18" ry="8" fill="#0d0d1a" stroke="#2d2d4e" strokeWidth="2" />

          {/* Body */}
          <ellipse cx="407" cy="292" rx="54" ry="58" fill="#1a1a2e" stroke="#2d2d4e" strokeWidth="2.5" />
          <path d="M407 238 L407 342" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.4" />
          <path
            d="M386 314 Q407 310 428 314 Q428 334 407 336 Q386 334 386 314Z"
            fill="#111"
            stroke="#2d2d4e"
            strokeWidth="1.5"
            opacity="0.7"
          />

          {/* Left arm + bag */}
          <path
            d="M460 276 Q480 290 486 310 Q488 322 482 326"
            stroke="#1a1a2e"
            strokeWidth="21"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d="M460 276 Q480 290 486 310 Q488 322 482 326"
            stroke="#2d2d4e"
            strokeWidth="18"
            strokeLinecap="round"
            fill="none"
          />
          <circle cx="481" cy="328" r="13" fill="#1a1a2e" stroke="#2d2d4e" strokeWidth="2" />
          <path
            d="M468 318 Q472 296 494 298 Q516 298 516 318 Q516 346 494 349 Q472 349 468 318Z"
            fill="#111"
            stroke="#2d2d4e"
            strokeWidth="2"
          />
          <line x1="470" y1="308" x2="514" y2="308" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.6" />
          <text
            x="492"
            y="332"
            textAnchor="middle"
            fontSize="15"
            fill="#ff3d6b"
            fontFamily="Nunito,sans-serif"
            fontWeight="900"
          >
            $
          </text>

          {/* Right arm (reaching) */}
          <g className={styles.reachArm}>
            <path
              d="M356 282 Q325 277 312 254 Q307 246 309 238"
              stroke="#1a1a2e"
              strokeWidth="21"
              strokeLinecap="round"
              fill="none"
            />
            <path
              d="M356 282 Q325 277 312 254 Q307 246 309 238"
              stroke="#2d2d4e"
              strokeWidth="18"
              strokeLinecap="round"
              fill="none"
            />
            <circle cx="309" cy="236" r="14" fill="#1a1a2e" stroke="#2d2d4e" strokeWidth="2" />
            <path d="M301 228 Q295 221 291 218" stroke="#2d2d4e" strokeWidth="5" strokeLinecap="round" />
            <path d="M305 225 Q300 217 298 213" stroke="#2d2d4e" strokeWidth="5" strokeLinecap="round" />
            <path d="M310 223 Q308 215 308 211" stroke="#2d2d4e" strokeWidth="5" strokeLinecap="round" />
            <path d="M316 225 Q317 217 321 214" stroke="#2d2d4e" strokeWidth="5" strokeLinecap="round" />
            <line
              x1="301"
              y1="224"
              x2="282"
              y2="250"
              stroke="#ffb830"
              strokeWidth="3"
              strokeLinecap="round"
            />
            <circle cx="282" cy="252" r="4" fill="#ffb830" />
          </g>

          {/* Head */}
          <circle cx="407" cy="212" r="56" fill="#1a1a2e" stroke="#2d2d4e" strokeWidth="2.5" />
          <path
            d="M355 204 Q358 185 407 182 Q456 185 459 204"
            fill="#0d0d1a"
            stroke="#2d2d4e"
            strokeWidth="2"
          />
          <ellipse cx="407" cy="165" rx="44" ry="28" fill="#0d0d1a" stroke="#2d2d4e" strokeWidth="2" />
          <line x1="370" y1="178" x2="368" y2="200" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />
          <line x1="382" y1="174" x2="380" y2="198" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />
          <line x1="395" y1="172" x2="394" y2="197" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />
          <line x1="407" y1="171" x2="407" y2="196" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />
          <line x1="419" y1="172" x2="420" y2="197" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />
          <line x1="432" y1="174" x2="434" y2="198" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />
          <line x1="444" y1="178" x2="446" y2="200" stroke="#2d2d4e" strokeWidth="1.5" opacity="0.55" />

          {/* Mask */}
          <rect x="364" y="200" width="86" height="34" rx="7" fill="#0d0d1a" stroke="#2d2d4e" strokeWidth="2" />

          {/* Eyes */}
          <g className={styles.thiefEyesG}>
            <ellipse cx="390" cy="216" rx="13" ry="11" fill="white" />
            <ellipse cx="424" cy="216" rx="13" ry="11" fill="white" />
            <line x1="379" y1="208" x2="392" y2="212" stroke="#1a1a2a" strokeWidth="3.5" strokeLinecap="round" />
            <line x1="435" y1="208" x2="422" y2="212" stroke="#1a1a2a" strokeWidth="3.5" strokeLinecap="round" />
            <circle cx="392" cy="218" r="7" fill="#0a0a0f" />
            <circle cx="422" cy="218" r="7" fill="#0a0a0f" />
            <circle cx="394" cy="214" r="2.5" fill="white" />
            <circle cx="424" cy="214" r="2.5" fill="white" />
          </g>

          {/* Mouth */}
          <g className={styles.thiefMouthG}>
            <path
              d="M390 238 Q407 248 424 238"
              stroke="#2d2d4e"
              strokeWidth="3.5"
              fill="none"
              strokeLinecap="round"
            />
          </g>

          {/* Sweat */}
          <g className={styles.sw1}>
            <path
              d="M455 190 Q458 181 461 190 Q461 198 458 198 Q455 198 455 190Z"
              fill="#7c3aed"
              opacity="0.85"
            />
          </g>
          <g className={styles.sw2}>
            <path
              d="M464 202 Q467 195 470 202 Q470 208 467 208 Q464 208 464 202Z"
              fill="#7c3aed"
              opacity="0.65"
            />
          </g>
        </g>
      </g>

      {/* Particles */}
      <circle className={styles.p1} cx="80" cy="340" r="2" fill="#00f5c4" opacity="0.4" />
      <circle className={styles.p2} cx="620" cy="320" r="1.5" fill="#7c3aed" opacity="0.5" />
      <circle className={styles.p3} cx="60" cy="260" r="2" fill="#00f5c4" opacity="0.3" />
      <circle className={styles.p4} cx="640" cy="240" r="1.5" fill="#ffb830" opacity="0.4" />

      {/* Binary */}
      <text x="30" y="150" fontFamily="'DM Mono',monospace" fontSize="9" fill="#00f5c4" opacity="0.06">
        10110
      </text>
      <text x="640" y="160" fontFamily="'DM Mono',monospace" fontSize="9" fill="#00f5c4" opacity="0.06">
        01001
      </text>
    </svg>
  );
}
