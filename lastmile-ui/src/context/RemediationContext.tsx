"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

interface RemediationContextValue {
  remediatedFindingIds: ReadonlySet<string>;
  /** Increments on every setRemediated mutation so consumers can depend on a primitive. */
  remediationVersion: number;
  isRemediated: (findingId: string) => boolean;
  setRemediated: (findingId: string, value: boolean) => void;
}

const RemediationContext = createContext<RemediationContextValue | null>(null);

export function RemediationProvider({ children }: { children: React.ReactNode }) {
  const [ids, setIds] = useState<Set<string>>(() => new Set());
  const [remediationVersion, setRemediationVersion] = useState(0);

  const isRemediated = useCallback(
    (findingId: string) => ids.has(findingId.trim()),
    [ids],
  );

  const setRemediated = useCallback((findingId: string, value: boolean) => {
    const key = findingId.trim();
    if (!key) return;
    setIds((prev) => {
      const next = new Set(prev);
      if (value) next.add(key);
      else next.delete(key);
      return next;
    });
    setRemediationVersion((v) => v + 1);
  }, []);

  const value = useMemo(
    () => ({
      remediatedFindingIds: ids,
      remediationVersion,
      isRemediated,
      setRemediated,
    }),
    [ids, remediationVersion, isRemediated, setRemediated],
  );

  return (
    <RemediationContext.Provider value={value}>{children}</RemediationContext.Provider>
  );
}

export function useRemediation() {
  const ctx = useContext(RemediationContext);
  if (!ctx) throw new Error("useRemediation requires RemediationProvider");
  return ctx;
}
