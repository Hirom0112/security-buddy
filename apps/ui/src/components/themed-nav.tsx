"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import styles from "@/app/dashboard.module.css";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard" },
  { href: "/campaigns", label: "Campaigns" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/patches", label: "Patches" },
] as const;

export function ThemedNav() {
  const pathname = usePathname() ?? "/";

  return (
    <nav className={styles.nav}>
      <Link href="/" className={styles.navBrand}>
        <div className={styles.shieldLogo}>
          <svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M20 2L3 9v14c0 9.4 7.2 18.1 17 20 9.8-1.9 17-10.6 17-20V9Z"
              fill="rgba(0,245,196,0.1)"
              stroke="#00f5c4"
              strokeWidth="1.8"
            />
            <path
              d="M20 6L7 12v11c0 7.2 5.6 13.8 13 15.4C27.4 36.8 33 30.2 33 23V12Z"
              fill="none"
              stroke="rgba(0,245,196,0.25)"
              strokeWidth="0.8"
            />
            <rect
              x="14"
              y="19"
              width="12"
              height="10"
              rx="2.5"
              fill="#00f5c4"
              opacity="0.9"
              style={{ animation: "lock-bob 2s ease-in-out infinite" }}
            />
            <path
              d="M16.5 19v-3a3.5 3.5 0 017 0v3"
              stroke="#00f5c4"
              strokeWidth="2"
              fill="none"
              strokeLinecap="round"
            />
            <circle cx="20" cy="24" r="1.8" fill="#0a0a0f" />
            <rect x="19.2" y="24" width="1.6" height="2.5" rx="0.5" fill="#0a0a0f" />
            <circle
              cx="20"
              cy="22"
              r="16"
              stroke="rgba(0,245,196,0.15)"
              strokeWidth="0.6"
              strokeDasharray="4 6"
              style={{
                transformOrigin: "20px 22px",
                animation: "ring-spin 8s linear infinite",
              }}
            />
          </svg>
        </div>
        <div className={styles.navBrandText}>
          <span className={styles.navBrandName}>Security Buddy</span>
        </div>
      </Link>

      <div className={styles.navLinks}>
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`${styles.navLink} ${isActive ? styles.navLinkActive : ""}`}
            >
              {item.label}
            </Link>
          );
        })}
      </div>

      <div className={styles.navRight}>
        <div className={styles.threatBadge}>
          <span
            className={styles.pulseDot}
            style={{ ["--accent" as string]: "var(--sb-neon)" }}
          />
          THREAT MONITOR LIVE
        </div>
        <form action="/logout" method="POST">
          <button type="submit" className={styles.signoutBtn}>
            Sign Out
          </button>
        </form>
      </div>
    </nav>
  );
}
