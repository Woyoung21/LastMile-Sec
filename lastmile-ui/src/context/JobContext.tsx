"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

export interface JobState {
  id: string | null;
  stage: string;
  progress: number;
  message: string;
  active: boolean;
}

interface JobContextValue {
  job: JobState;
  setJob: (partial: Partial<JobState> | ((j: JobState) => JobState)) => void;
  startSimulatedJob: () => void;
  resetJob: () => void;
}

const JobContext = createContext<JobContextValue | null>(null);

const initial: JobState = {
  id: null,
  stage: "idle",
  progress: 0,
  message: "",
  active: false,
};

export function JobProvider({ children }: { children: React.ReactNode }) {
  const [job, setJobState] = useState<JobState>(initial);

  const setJob = useCallback(
    (u: Partial<JobState> | ((j: JobState) => JobState)) => {
      setJobState((prev) => (typeof u === "function" ? u(prev) : { ...prev, ...u }));
    },
    [],
  );

  const startSimulatedJob = useCallback(() => {
    const id = crypto.randomUUID();
    setJobState({
      id,
      stage: "Ingestion",
      progress: 4,
      message: "Staging raw evidence buffers…",
      active: true,
    });
  }, []);

  const resetJob = useCallback(() => {
    setJobState(initial);
  }, []);

  const value = useMemo(
    () => ({ job, setJob, startSimulatedJob, resetJob }),
    [job, setJob, startSimulatedJob, resetJob],
  );

  return <JobContext.Provider value={value}>{children}</JobContext.Provider>;
}

export function useJob() {
  const ctx = useContext(JobContext);
  if (!ctx) throw new Error("useJob requires JobProvider");
  return ctx;
}
