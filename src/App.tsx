import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Dashboard } from "./Dashboard";
import type { GuardStatus } from "./types";

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
    />
  );
}
