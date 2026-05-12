// Themed page shell — cyber-noir background + nav + compact hero, shared by
// all authenticated routes other than the dashboard (which has its own hero).
// Renders server-side; client interactivity lives in ThemedNav.

import { Bebas_Neue, DM_Mono, Nunito } from "next/font/google";
import { ThemedNav } from "@/components/themed-nav";
import styles from "@/app/dashboard.module.css";

const bebasNeue = Bebas_Neue({
  weight: "400",
  subsets: ["latin"],
  variable: "--font-bebas",
  display: "swap",
});
const dmMono = DM_Mono({
  weight: ["400", "500"],
  subsets: ["latin"],
  variable: "--font-dm-mono",
  display: "swap",
});
const nunito = Nunito({
  weight: ["700", "800", "900"],
  subsets: ["latin"],
  variable: "--font-nunito",
  display: "swap",
});

const PARTICLES = [
  { left: "8%", top: "60%", size: 2, color: "#00f5c4", dur: 6, delay: 0 },
  { left: "20%", top: "70%", size: 1.5, color: "#7c3aed", dur: 8, delay: 1.5 },
  { left: "75%", top: "65%", size: 2, color: "#00f5c4", dur: 7, delay: 0.8 },
  { left: "88%", top: "55%", size: 1, color: "#ffb830", dur: 5, delay: 2 },
  { left: "50%", top: "75%", size: 1.5, color: "#ff3d6b", dur: 9, delay: 3 },
];

type ThemedShellProps = {
  eyebrow: string;
  title: string;
  meta?: React.ReactNode;
  children: React.ReactNode;
};

export function ThemedShell({
  eyebrow,
  title,
  meta,
  children,
}: ThemedShellProps) {
  return (
    <main
      className={`${styles.root} ${bebasNeue.variable} ${dmMono.variable} ${nunito.variable}`}
    >
      <div className={styles.gridBg} aria-hidden="true" />
      <div className={styles.scanlines} aria-hidden="true" />
      {PARTICLES.map((p, i) => (
        <span
          key={i}
          className={styles.particle}
          aria-hidden="true"
          style={{
            left: p.left,
            top: p.top,
            width: `${p.size}px`,
            height: `${p.size}px`,
            background: p.color,
            animationDuration: `${p.dur}s`,
            animationDelay: `${p.delay}s`,
          }}
        />
      ))}

      <ThemedNav />

      <div className={styles.pageHero}>
        <div className={styles.heroBg} />
        <div className={styles.heroBgLine} />
        <div className={styles.heroInner}>
          <div className={styles.heroEyebrow}>{eyebrow}</div>
          <div className={styles.pageHeroTitle}>{title}</div>
          {meta ? <div className={styles.pageHeroMeta}>{meta}</div> : null}
        </div>
      </div>

      <div className={styles.main}>{children}</div>
    </main>
  );
}
