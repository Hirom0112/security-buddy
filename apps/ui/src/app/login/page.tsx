import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { Bebas_Neue, DM_Mono, Nunito } from "next/font/google";
import { getSession } from "@/lib/auth/session";
import { LoginScene } from "./scene";
import { ThemedLoginForm } from "./login-form-themed";
import styles from "./login.module.css";

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

export default async function LoginPage() {
  // If already authenticated, redirect to dashboard
  const session = await getSession();
  if (session !== null) {
    redirect("/");
  }

  // CSRF cookie is issued by middleware on unauthenticated GET /login.
  // Middleware mutates request.cookies via NextResponse.next({ request }),
  // so cookies().get() here sees the fresh value on the very first hit.
  const cookieStore = await cookies();
  const csrfToken = cookieStore.get("sb_csrf")?.value ?? "";

  return (
    <main
      className={`${styles.root} ${bebasNeue.variable} ${dmMono.variable} ${nunito.variable}`}
    >
      <div className={styles.gridBg} aria-hidden="true" />
      <div className={styles.vignette} aria-hidden="true" />
      <div className={styles.scanlines} aria-hidden="true" />

      <div className={styles.page}>
        <div className={styles.hero}>
          <div className={styles.scene}>
            <LoginScene />
          </div>

          <div className={styles.loginCard}>
            <div className={styles.eyebrow}>{"// Access Portal"}</div>
            <h1 className={styles.title}>Sign In</h1>
            <p className={styles.sub}>
              Adversarial evaluation platform. Authorized only.
            </p>
            <ThemedLoginForm csrfToken={csrfToken} />
          </div>
        </div>

        <div className={styles.statusBar}>
          <span className={styles.statusDot} aria-hidden="true" />
          <span className={styles.statusText}>
            THREAT MONITOR ACTIVE — 0 BREACHES DETECTED
          </span>
        </div>
      </div>
    </main>
  );
}
