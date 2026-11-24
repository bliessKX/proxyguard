export type TargetProcess = { name: string; path: string };
export type LogEntry = { time: number; level: "ok" | "warn" | "error"; message: string };
export type GuardState = "starting" | "protected" | "blocked" | "unknown";
export type GuardStatus = {
  state: GuardState;
  message: string;
  publicIp: string | null;
  countryCode: string | null;
  country: string | null;
  allowedCountry: string;
  blocked: boolean;
  blockError: string | null;
  knownPaths: string[];
  running: TargetProcess[];
  checkedAt: number;
  intervalSeconds: number;
  logs: LogEntry[];
};
