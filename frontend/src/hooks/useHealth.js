import { useEffect, useState } from "react";
import { api } from "../services/api.js";

/** Polls API liveness + DB readiness. status: "loading" | "ok" | "degraded" | "down". */
export default function useHealth(intervalMs = 15000) {
  const [state, setState] = useState({ status: "loading", version: null, error: null });

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const live = await api.health();
        try {
          await api.ready();
          if (!cancelled) setState({ status: "ok", version: live.version, error: null });
        } catch (err) {
          if (!cancelled) setState({ status: "degraded", version: live.version, error: err });
        }
      } catch (err) {
        if (!cancelled) setState({ status: "down", version: null, error: err });
      }
    }

    check();
    const id = setInterval(check, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [intervalMs]);

  return state;
}
