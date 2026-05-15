"use client";

import { useState } from "react";
import { dismissVulnerability } from "./actions";
import styles from "@/app/dashboard.module.css";

/**
 * Confirmation dialog wrapper around the dismiss server action.
 *
 * Pattern: render a button; on click reveal an inline form that asks
 * for a reason and submits via the server action. We use the native
 * <dialog> element so we get focus trapping and Escape-to-close for
 * free without dragging in a modal library.
 */
export function DismissForm({
  vulnerabilityId,
}: {
  vulnerabilityId: string;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const isValid = reason.trim().length >= 4;

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
          setError(null);
        }}
        className={`${styles.btn} ${styles.btnDanger} ${styles.btnLg}`}
      >
        Dismiss
      </button>
      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="dismiss-dialog-title"
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            display: "grid",
            placeItems: "center",
            zIndex: 50,
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setOpen(false);
          }}
        >
          <form
            className={styles.panel}
            style={{ maxWidth: "32rem", width: "90%" }}
            onSubmit={async (e) => {
              e.preventDefault();
              if (!isValid) return;
              setSubmitting(true);
              setError(null);
              try {
                const fd = new FormData();
                fd.set("id", vulnerabilityId);
                fd.set("reason", reason);
                await dismissVulnerability(fd);
                setOpen(false);
              } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
                setSubmitting(false);
              }
            }}
          >
            <div className={styles.panelHeader}>
              <div className={styles.panelHeaderLeft}>
                <div
                  id="dismiss-dialog-title"
                  className={styles.panelTitle}
                >
                  Dismiss this finding?
                </div>
                <div className={styles.panelSubtitle}>
                  The reason is appended to the vulnerability&rsquo;s audit
                  trail with your timestamp. Status is unchanged.
                </div>
              </div>
            </div>
            <div className={styles.panelBody}>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why are you dismissing this? (min 4 characters)"
                rows={4}
                required
                minLength={4}
                style={{
                  width: "100%",
                  padding: "0.5rem",
                  fontFamily: "inherit",
                  fontSize: "0.95rem",
                }}
              />
              {error && (
                <div
                  style={{ color: "var(--sb-danger)", marginTop: "0.5rem" }}
                  role="alert"
                >
                  {error}
                </div>
              )}
              <div
                style={{
                  display: "flex",
                  gap: "0.5rem",
                  marginTop: "1rem",
                  justifyContent: "flex-end",
                }}
              >
                <button
                  type="button"
                  className={styles.btn}
                  onClick={() => setOpen(false)}
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className={`${styles.btn} ${styles.btnDanger}`}
                  disabled={!isValid || submitting}
                >
                  {submitting ? "Recording…" : "Confirm dismiss"}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}
    </>
  );
}
