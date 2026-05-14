"use client";

import { useState } from "react";
import styles from "@/app/dashboard.module.css";

const DEFAULT_TARGET_URL =
  "https://clinical-copilot-openemr-production.up.railway.app/interface/login/login.php?site=default";

export function TargetUrl() {
  const [targetUrl, setTargetUrl] = useState<string>(DEFAULT_TARGET_URL);

  return (
    <>
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
    </>
  );
}
