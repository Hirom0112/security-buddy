/**
 * Full loop e2e test — Slice 7 DoD.
 *
 * Exercises the full Security Buddy security loop end-to-end:
 *
 *   log in -> trigger campaign -> wait for verdict -> confirm finding
 *   -> see PR row in /patches -> (operator merges on GitHub) -> regression
 *   sweep enqueues -> /vulnerabilities/[id]/diff shows a terminal banner
 *   (RESOLVED / SECURITY REGRESSED / UNSTABLE / OVER_FIT).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * SKIPPED BY DEFAULT.
 *
 * This test cannot run in CI today — it requires a fully-wired local stack
 * (Postgres, Redis, arq worker, FastAPI, Next.js dev server) plus a reachable
 * OpenEMR target and a valid GITHUB_PAT scoped to the patch-target fork.
 *
 * It runs only when the env var PLAYWRIGHT_E2E=1 is set. CI does not set
 * it; the operator opts in locally.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * How to run it (operator checklist):
 *
 *   1. Stand up the platform:
 *        docker compose up -d                      # postgres + redis
 *        cd apps/api && alembic upgrade head
 *        cd apps/api && uvicorn src.main:app --reload
 *        cd apps/api && arq src.workers.WorkerSettings
 *        cd apps/ui  && pnpm dev
 *
 *   2. Confirm the OpenEMR target is reachable from the API container:
 *        TARGET_BASE_URL=...  TARGET_LOGIN_USER=...  TARGET_LOGIN_PASSWORD=...
 *
 *   3. Confirm GITHUB_PAT is set (Patch Agent needs it to open PRs).
 *
 *   4. Run:
 *        PLAYWRIGHT_E2E=1 \
 *        PLAYWRIGHT_OPERATOR_PASSWORD=<the operator password> \
 *        PLAYWRIGHT_BASE_URL=http://localhost:3000 \
 *        PLAYWRIGHT_CAMPAIGN_TIMEOUT_MS=600000 \
 *        WAIT_FOR_MERGE=1 \
 *        pnpm test:e2e tests/e2e/full-loop.spec.ts
 *
 *      WAIT_FOR_MERGE=1 pauses the test after a PR appears so the operator
 *      can merge it on GitHub. Drop the flag to stop at the "PR visible"
 *      assertion (still a useful smoke).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * Automation boundaries:
 *
 *   - Login → campaign launch → verdict polling → confirm → patch row:
 *     FULLY AUTOMATED.
 *   - GitHub merge: MANUAL. The platform does not (and should not) merge
 *     PRs on behalf of the operator. The test pauses via page.pause() so
 *     the operator can merge in the GitHub UI. The webhook back to
 *     /api/v1/webhooks/github then triggers the regression sweep.
 *   - Regression banner: FULLY AUTOMATED once the webhook fires.
 *
 * The whole flow can take 5-15 minutes depending on the Red Team budget and
 * LLM latency. Set PLAYWRIGHT_CAMPAIGN_TIMEOUT_MS accordingly.
 */

import { expect, test } from "@playwright/test";

const RUN_E2E = process.env["PLAYWRIGHT_E2E"] === "1";
const OPERATOR_PASSWORD = process.env["PLAYWRIGHT_OPERATOR_PASSWORD"] ?? "";
const CAMPAIGN_TIMEOUT_MS = Number(
  process.env["PLAYWRIGHT_CAMPAIGN_TIMEOUT_MS"] ?? 5 * 60 * 1000,
);
const REGRESSION_TIMEOUT_MS = Number(
  process.env["PLAYWRIGHT_REGRESSION_TIMEOUT_MS"] ?? 10 * 60 * 1000,
);
const WAIT_FOR_MERGE = process.env["WAIT_FOR_MERGE"] === "1";

test.describe("Full security loop (Slice 7 DoD)", () => {
  test.skip(
    !RUN_E2E,
    "Set PLAYWRIGHT_E2E=1 and stand up the full stack (see file docstring).",
  );

  // The full loop is intentionally serialised — fully_parallel is already
  // false in playwright.config.ts, but we make it explicit here.
  test.describe.configure({ mode: "serial" });

  test("log in -> campaign -> verdict -> confirm -> PR -> regression -> banner", async ({
    page,
  }) => {
    test.setTimeout(CAMPAIGN_TIMEOUT_MS + REGRESSION_TIMEOUT_MS + 60_000);

    expect(
      OPERATOR_PASSWORD,
      "PLAYWRIGHT_OPERATOR_PASSWORD must be set",
    ).not.toBe("");

    // ── 1. Unauthenticated / redirects to /login ────────────────────────
    await page.context().clearCookies();
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);

    // ── 2. Log in with operator password ────────────────────────────────
    await page.getByLabel(/password/i).fill(OPERATOR_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(
      page.getByRole("heading", { name: /security buddy/i }),
    ).toBeVisible();

    // ── 3. Open the Start Campaign modal ────────────────────────────────
    await page.getByRole("button", { name: /start campaign/i }).click();
    await expect(
      page.getByRole("dialog", { name: /start campaign/i }),
    ).toBeVisible();

    // Budget 1.00 USD; mode = Live; targeting = New campaign; no subcat.
    await page.getByLabel(/budget \(usd\)/i).fill("1");

    const modeGroup = page.getByRole("radiogroup", { name: /^mode$/i });
    await modeGroup.getByRole("radio", { name: /^live$/i }).click();

    const targetingGroup = page.getByRole("radiogroup", {
      name: /^targeting$/i,
    });
    await targetingGroup
      .getByRole("radio", { name: /^new campaign$/i })
      .click();

    // Submit. The modal navigates to /campaigns/[id].
    await page.getByRole("button", { name: /^launch$/i }).click();
    await expect(page).toHaveURL(/\/campaigns\//, { timeout: 30_000 });

    // ── 4. Wait for the campaign to produce a confirmable vuln ──────────
    // The live status component on the campaign page eventually shows
    // either "awaiting review" or transitions the campaign to a
    // terminal state. We poll /vulnerabilities for a draft row, which is
    // the state the operator acts on next.
    const draftLink = await pollForDraftVulnerability(
      page,
      CAMPAIGN_TIMEOUT_MS,
    );

    // ── 5. Open the draft and click Confirm finding ─────────────────────
    await draftLink.click();
    await expect(page).toHaveURL(/\/vulnerabilities\/[0-9a-f-]+$/);

    const confirmButton = page.getByRole("button", {
      name: /confirm finding/i,
    });
    await expect(confirmButton).toBeVisible();
    await confirmButton.click();

    // After confirmation the page re-renders; the alert callout for the
    // operator decision should no longer be visible.
    await expect(
      page.getByText(/operator decision required/i),
    ).toBeHidden({ timeout: 15_000 });

    // ── 6. Wait for a Patch Agent PR row in /patches ────────────────────
    // The Patch Agent runs asynchronously after confirm. Poll the
    // pending-review list until a row appears.
    await pollForPendingPatchRow(page, CAMPAIGN_TIMEOUT_MS);

    // ── 7. Operator merge step (manual) ─────────────────────────────────
    if (!WAIT_FOR_MERGE) {
      test.info().annotations.push({
        type: "manual-step-skipped",
        description:
          "Stopped at 'PR visible'. Set WAIT_FOR_MERGE=1 to continue through merge + regression banner.",
      });
      return;
    }

    // page.pause() opens the Playwright Inspector. The operator merges the
    // PR on GitHub, then clicks Resume. The webhook flips the patch row
    // and enqueues the regression sweep.
    // eslint-disable-next-line no-console
    console.log(
      "[full-loop] Merge the open PR on GitHub now, then click Resume in the Inspector.",
    );
    await page.pause();

    // ── 8. Verify the regression banner ─────────────────────────────────
    // Grab the vulnerability id back out of the current URL by going to
    // the vulnerabilities list and clicking the freshly-merged row. The
    // diff page hosts the terminal banner.
    await page.goto("/vulnerabilities");
    // The most-recently-acted-on vulnerability is the one we just merged
    // a patch for. Click its row; the page links by vuln id.
    const firstRow = page.locator("table tbody tr").first();
    const idCell = firstRow.locator("td").first();
    await idCell.locator("a").click();
    await expect(page).toHaveURL(/\/vulnerabilities\/[0-9a-f-]+$/);

    // Navigate to the diff view.
    await page.goto(page.url() + "/diff");
    await expect(page).toHaveURL(/\/vulnerabilities\/[0-9a-f-]+\/diff$/);

    // Wait for the StatusBanner to render with a terminal label. The five
    // possible terminal labels live in OUTCOME_META on the diff page.
    const banner = page.getByText(
      /^(RESOLVED|SECURITY REGRESSED|UNSTABLE|TARGET UNAVAILABLE|OVER_FIT.*)$/,
    );
    await expect(banner.first()).toBeVisible({
      timeout: REGRESSION_TIMEOUT_MS,
    });

    // Permissive assertion: as long as we're NOT still showing the
    // "no regression sweep" empty state, the loop closed.
    await expect(
      page.getByText(/no regression sweep has run/i),
    ).toBeHidden();
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────

/**
 * Poll /vulnerabilities until at least one row is in the "Awaiting Your
 * Decision" panel (i.e. status=draft). Returns a locator to the first
 * draft row's id link.
 */
async function pollForDraftVulnerability(
  page: import("@playwright/test").Page,
  timeoutMs: number,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await page.goto("/vulnerabilities");
    // The draft panel is only rendered when drafts.length > 0.
    const draftPanel = page.getByText(/awaiting your decision/i);
    if (await draftPanel.isVisible().catch(() => false)) {
      const rows = page.locator("table tbody tr");
      const first = rows.first();
      if ((await rows.count()) > 0) {
        return first.locator("td").first().locator("a");
      }
    }
    await page.waitForTimeout(10_000);
  }
  throw new Error(
    `No draft vulnerability appeared within ${timeoutMs}ms. ` +
      `Check the API + arq worker logs.`,
  );
}

/**
 * Poll /patches until the "Pending Review" panel has at least one row.
 */
async function pollForPendingPatchRow(
  page: import("@playwright/test").Page,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await page.goto("/patches");
    const pendingHeader = page.getByText(/pending review/i);
    if (await pendingHeader.isVisible().catch(() => false)) {
      const rows = page.locator("table tbody tr");
      if ((await rows.count()) > 0) return;
    }
    await page.waitForTimeout(10_000);
  }
  throw new Error(
    `No pending patch row appeared within ${timeoutMs}ms. ` +
      `Confirm GITHUB_PAT is configured and the Patch Agent ran.`,
  );
}
