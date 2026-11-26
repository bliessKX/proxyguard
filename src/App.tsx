import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Dashboard } from "./Dashboard";
import type { GuardStatus, TargetActions, TargetProcess } from "./types";

// Tauri injects __TAURI_INTERNALS__ only inside the desktop window.
const IN_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export default function App() {
  const [status, setStatus] = useState<GuardStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!IN_TAURI) {
      setError("这是浏览器页面，无法调用本地守护功能。请关闭浏览器标签页，使用 ProxyGuard 桌面窗口。");
      return;
    }
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    listen<GuardStatus>("guard-status", (e) => setStatus(e.payload))
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch((e) => setError(String(e)));
    invoke<GuardStatus>("get_status")
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch((e) => setError(String(e)));
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  async function changeCountry(code: string) {
    try {
      setStatus(await invoke<GuardStatus>("set_allowed_country", { code }));
    } catch (e) {
      setError(String(e));
    }
  }

  async function checkNow() {
    setBusy(true);
    try {
      await invoke("check_now");
    } catch (e) {
      setError(String(e));
    } finally {
      window.setTimeout(() => setBusy(false), 1500);
    }
  }

  // Runs a command that returns a fresh status; failures show in the notice bar.
  async function act(command: string, args: Record<string, unknown>): Promise<boolean> {
    setError(null);
    try {
      setStatus(await invoke<GuardStatus>(command, args));
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    }
  }

  const actions: TargetActions = {
    pickFile: async () => {
      setError(null);
      try {
        return await invoke<string | null>("pick_file");
      } catch (e) {
        setError(String(e));
        return null;
      }
    },
    listProcesses: async () => {
      setError(null);
      try {
        return await invoke<TargetProcess[]>("list_processes");
      } catch (e) {
        setError(String(e));
        return [];
      }
    },
    add: (path, guard, spoof) => act("add_target", { path, guard, spoof }),
    remove: async (path) => {
      await act("remove_target", { path });
    },
    setFlags: async (path, guard, spoof) => {
      await act("set_target_flags", { path, guard, spoof });
    },
    launch: async (path) => {
      await act("launch_target", { path });
    },
  };

  if (!status) {
    return (
      <div className="boot">
        <span className="boot-text">{error ?? "ProxyGuard 正在启动…"}</span>
      </div>
    );
  }

  return (
    <Dashboard
      status={status}
      error={error}
      busy={busy}
      onCountryChange={changeCountry}
      onCheckNow={checkNow}
      actions={actions}
    />
  );
}
