"use client";

import { useEffect, useState } from "react";
import styles from "@/app/dashboard.module.css";

const SLOGANS = [
  "We Catch What Others Miss",
  "Your AI's Worst Nightmare",
] as const;

const DEFAULT_TARGET_URL =
  "https://clinical-copilot-openemr-production.up.railway.app/interface/login/login.php?site=default";

export function DashboardHero() {
  const [sloganIdx, setSloganIdx] = useState(0);
  const [phase, setPhase] = useState<"in" | "out">("in");
  const [now, setNow] = useState<string>("");
  const [targetUrl, setTargetUrl] = useState<string>(DEFAULT_TARGET_URL);

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setNow(d.toLocaleTimeString("en-US", { hour12: false }) + " UTC");
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => {
      setPhase("out");
      window.setTimeout(() => {
        setSloganIdx((i) => (i + 1) % SLOGANS.length);
        setPhase("in");
      }, 400);
    }, 5000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className={styles.hero}>
      <div className={styles.heroBg} />
      <div className={styles.heroBgLine} />
      <div className={styles.heroInner}>
        <div className={styles.heroSlogan}>
          <span
            key={`${sloganIdx}-${phase}`}
            className={`${styles.sloganLine} ${
              phase === "in" ? styles.sloganIn : styles.sloganOut
            }`}
          >
            {SLOGANS[sloganIdx]}
          </span>
        </div>
        <div className={styles.heroSub}>
          <span className={styles.pulseDot} />
          <span>System Online</span>
          <span className={styles.heroSubDivider} />
          <span>{now || "—"}</span>
          <span className={styles.heroSubDivider} />
          <span className={styles.targetLabel}>Target&nbsp;//</span>
          <form
            className={styles.targetForm}
            onSubmit={(e) => e.preventDefault()}
            role="search"
            aria-label="Attack target URL"
          >
            <svg
              className={styles.targetIcon}
              viewBox="0 0 16 16"
              fill="none"
              aria-hidden="true"
            >
              <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
              <circle cx="8" cy="8" r="2.2" stroke="currentColor" strokeWidth="1.4" />
              <path
                d="M8 1v2M8 13v2M1 8h2M13 8h2"
                stroke="currentColor"
                strokeWidth="1.4"
                strokeLinecap="round"
              />
            </svg>
            <input
              type="url"
              className={styles.targetInput}
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://target.example.com"
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="button"
              className={styles.targetReset}
              onClick={() => setTargetUrl(DEFAULT_TARGET_URL)}
              title="Reset to OpenEMR Clinical Co-Pilot"
              aria-label="Reset target to default"
            >
              ↺
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
