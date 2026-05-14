import {
  countDraftVulnerabilities,
  getActiveCampaign,
} from "@/lib/db/queries";
import { StatusBadge } from "./status-badge";
import { HeroClock } from "./hero-clock";
import { TargetUrl } from "./target-url";
import styles from "@/app/dashboard.module.css";

/**
 * Server component. Reads the active-campaign + draft-vuln state and renders
 * the dashboard hero — brand slogan rotator, status badge, target, clock.
 *
 * Reads are direct Postgres (see lib/db/queries). If the DB is unreachable we
 * degrade silently to a neutral "STATUS UNKNOWN" badge so the hero still
 * paints.
 */
export async function DashboardHero() {
  let activeCampaign = null;
  let draftCount = 0;
  let dbOk = true;

  try {
    [activeCampaign, draftCount] = await Promise.all([
      getActiveCampaign(),
      countDraftVulnerabilities(),
    ]);
  } catch {
    dbOk = false;
  }

  return (
    <div className={styles.hero}>
      <div className={styles.heroBg} />
      <div className={styles.heroBgLine} />
      <div className={styles.heroInner}>
        <div className={styles.heroSlogan}>
          <span
            className={styles.sloganRotator}
            aria-label="We Catch What Others Miss. Your AI's Worst Nightmare."
          >
            <span className={styles.sloganRotatorA} aria-hidden="true">
              We Catch What Others Miss
            </span>
            <span className={styles.sloganRotatorB} aria-hidden="true">
              Your AI&rsquo;s Worst Nightmare
            </span>
          </span>
        </div>
        <div className={styles.heroSub}>
          {dbOk ? (
            <StatusBadge
              activeCampaign={
                activeCampaign === null
                  ? null
                  : {
                      id: activeCampaign.id,
                      target_subcategory: activeCampaign.target_subcategory,
                      status: activeCampaign.status,
                    }
              }
              draftVulnCount={draftCount}
            />
          ) : (
            <span
              className={`${styles.statusBadge} ${styles.statusBadgeAmber}`}
              role="status"
            >
              <span
                className={`${styles.statusBadgeDot} ${styles.statusBadgeDotAmber}`}
              />
              STATUS UNKNOWN
            </span>
          )}
          <span className={styles.heroSubDivider} />
          <HeroClock />
          <span className={styles.heroSubDivider} />
          <TargetUrl />
        </div>
      </div>
    </div>
  );
}
