export type TargetProcess = { name: string; path: string };
export type TargetRow = {
  path: string;
  name: string;
  /** Auto-registered codex / claude: always guarded, cannot be removed. */
  builtin: boolean;
  guard: boolean;
  spoof: boolean;
  running: boolean;
};
export type LaunchRecord = { path: string; name: string; timezone: string; time: number };
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
  targets: TargetRow[];
  /** IANA timezone of the current egress IP (null while not allowed / unknown). */
  spoofTimezone: string | null;
  /** Egress IP stable inside the allowed country: spoofed launches are enabled. */
  spoofReady: boolean;
  stableStreak: number;
  stableNeeded: number;
  launches: LaunchRecord[];
};

export type TargetActions = {
  pickFile: () => Promise<string | null>;
  listProcesses: () => Promise<TargetProcess[]>;
  add: (path: string, guard: boolean, spoof: boolean) => Promise<boolean>;
  remove: (path: string) => Promise<void>;
  setFlags: (path: string, guard: boolean, spoof: boolean) => Promise<void>;
  launch: (path: string) => Promise<void>;
};
