export type TraceStatus = "success" | "fail" | "info";

/** One row of the Key Gen Process debugger. Every value shown comes from a real computation. */
export type TraceStep = {
  title: string;
  actor: string;
  algorithm: string;
  input: string;
  output: string;
  verification: string;
  failureMode: string;
  status: TraceStatus;
  /** Which literature-survey paper motivated this step. */
  paper?: string;
};

export type Trace = TraceStep[];

/** A record of key material being created, used, or erased; drives the "deleted keys" log. */
export type KeyEvent = {
  kind: "created" | "erased" | "ratchet" | "skipped" | "used";
  label: string;
  preview: string;
};
