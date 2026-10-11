import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Fetch on mount, then re-fetch every `intervalMs` while `shouldPoll(data)`
 * is true. Polling stops by itself once the data settles (e.g. a scan
 * finishes), so a finished page makes no further requests.
 */
export function usePoll<T>(
  load: () => Promise<T>,
  intervalMs: number,
  shouldPoll: (data: T) => boolean,
  deps: unknown[],
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const loadRef = useRef(load);
  const pollRef = useRef(shouldPoll);
  loadRef.current = load;
  pollRef.current = shouldPoll;

  const refresh = useCallback(async () => {
    try {
      const next = await loadRef.current();
      setData(next);
      setError(null);
      return next;
    } catch (err) {
      setError(err as Error);
      return null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setData(null);

    const tick = async () => {
      const next = await refresh();
      if (cancelled) return;
      if (next === null || pollRef.current(next)) timer = setTimeout(tick, intervalMs);
    };
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, refresh };
}
