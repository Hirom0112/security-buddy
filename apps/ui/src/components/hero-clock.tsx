"use client";

import { useEffect, useState } from "react";

export function HeroClock() {
  const [now, setNow] = useState<string>("");

  useEffect(() => {
    const tick = (): void => {
      const d = new Date();
      setNow(d.toLocaleTimeString("en-US", { hour12: false }) + " UTC");
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, []);

  return <span>{now || "—"}</span>;
}
