"use client";

// Opens an EventSource against /api/campaigns/{id}/events and triggers
// router.refresh() on each `update` frame. The server emits one update per
// detected change (status flip, new attack, new verdict) and closes the
// stream with an `end` event once the campaign reaches a terminal status.
// EventSource handles reconnects natively; we stop reconnecting once the
// stream signals end, the campaign is terminal at mount time, or the
// component unmounts.

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

interface Props {
  campaignId: string;
  // Whether the campaign is already in a terminal status at SSR time.
  // When true we don't open a stream at all — saves a connection.
  isTerminal: boolean;
}

type ConnState = "connecting" | "live" | "ended" | "error";

export function CampaignLiveRefresh({ campaignId, isTerminal }: Props) {
  const router = useRouter();
  const [state, setState] = useState<ConnState>(
    isTerminal ? "ended" : "connecting"
  );
  const closedRef = useRef(false);

  useEffect(() => {
    if (isTerminal) return;
    closedRef.current = false;

    const url = `/api/campaigns/${encodeURIComponent(campaignId)}/events`;
    const es = new EventSource(url, { withCredentials: true });

    const onOpen = () => setState("live");
    const onUpdate = () => {
      router.refresh();
    };
    const onEnd = () => {
      closedRef.current = true;
      setState("ended");
      es.close();
      // Final refresh in case the very last frame and the end frame
      // arrived together — guarantees the UI matches DB on close.
      router.refresh();
    };
    const onErr = () => {
      // EventSource auto-reconnects on transient errors; only mark as
      // errored if the connection has been explicitly closed.
      if (closedRef.current || es.readyState === EventSource.CLOSED) {
        setState("error");
      }
    };

    es.addEventListener("open", onOpen);
    es.addEventListener("update", onUpdate);
    es.addEventListener("end", onEnd);
    es.addEventListener("error", onErr);

    return () => {
      closedRef.current = true;
      es.removeEventListener("open", onOpen);
      es.removeEventListener("update", onUpdate);
      es.removeEventListener("end", onEnd);
      es.removeEventListener("error", onErr);
      es.close();
    };
  }, [campaignId, isTerminal, router]);

  const dotColor =
    state === "live"
      ? "var(--accent-neon, #00ff9c)"
      : state === "connecting"
        ? "var(--accent-amber, #ffb347)"
        : state === "error"
          ? "var(--accent-danger, #ff5470)"
          : "var(--muted, #6b7280)";

  const label =
    state === "live"
      ? "LIVE"
      : state === "connecting"
        ? "CONNECTING"
        : state === "ended"
          ? "FINAL"
          : "OFFLINE";

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.45rem",
        fontFamily: "var(--font-mono, ui-monospace, monospace)",
        fontSize: "0.7rem",
        letterSpacing: "0.08em",
        color: "var(--muted, #6b7280)",
      }}
      aria-live="polite"
    >
      <span
        aria-hidden
        style={{
          width: 8,
          height: 8,
          borderRadius: 999,
          background: dotColor,
          boxShadow:
            state === "live" ? `0 0 6px ${dotColor}` : "none",
        }}
      />
      {label}
    </span>
  );
}
