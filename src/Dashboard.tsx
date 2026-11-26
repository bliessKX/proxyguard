import { useState } from "react";
import type { CSSProperties } from "react";
import type { GuardState, GuardStatus, LogEntry, TargetActions, TargetProcess, TargetRow } from "./types";

export const COUNTRIES: [string, string][] = [
  ["US", "美国"], ["JP", "日本"], ["SG", "新加坡"], ["MY", "马来西亚"], ["KR", "韩国"],
  ["GB", "英国"], ["DE", "德国"], ["FR", "法国"], ["NL", "荷兰"], ["CA", "加拿大"],
  ["AU", "澳大利亚"], ["CN", "中国"],
];

const HEADLINE: Record<GuardState, string> = {
  starting: "正在确认出口国家",
  protected: "出口在允许范围内",
  blocked: "VPN 已断开，目标程序已断网",
  unknown: "无法确认出口国家，已先行断网",
};

const WORD: Record<GuardState, string> = {
  starting: "检测中",
  protected: "放行",
  blocked: "断网",
  unknown: "待确认",
};

type Props = {
  status: GuardStatus;
  error: string | null;
  busy: boolean;
  onCountryChange: (code: string) => void;
  onCheckNow: () => void;
  actions: TargetActions;
};

function clock(secs: number): string {
  return secs ? new Date(secs * 1000).toLocaleTimeString("zh-CN", { hour12: false }) : "—";
}

// 60 ticks around the dial; every fifth tick is a major mark.
const TICKS = Array.from({ length: 60 }, (_, i) => {
  const angle = (i / 60) * Math.PI * 2 - Math.PI / 2;
  const major = i % 5 === 0;
  const inner = major ? 82 : 91;
  const outer = 100;
  const c = 110;
  return {
    i,
    major,
    x1: c + inner * Math.cos(angle),
    y1: c + inner * Math.sin(angle),
    x2: c + outer * Math.cos(angle),
    y2: c + outer * Math.sin(angle),
  };
});

function Dial({ state }: { state: GuardState }) {
  return (
    <div className="dial" data-state={state} aria-hidden="true">
      <svg viewBox="0 0 220 220">
        <circle className="dial-track" cx="110" cy="110" r="66" />
        {TICKS.map((t) => (
          <line
            key={t.i}
            className={t.major ? "tick major" : "tick"}
            style={{ "--i": t.i } as CSSProperties}
            x1={t.x1}
            y1={t.y1}
            x2={t.x2}
            y2={t.y2}
          />
        ))}
      </svg>
      <span className="dial-word">{WORD[state]}</span>
    </div>
  );
}

function Hero({ status, onCountryChange }: Pick<Props, "status" | "onCountryChange">) {
  const countryLabel = status.countryCode
    ? `${status.country || "未知"}（${status.countryCode}）`
    : "—";
  const options = COUNTRIES.some(([c]) => c === status.allowedCountry)
    ? COUNTRIES
    : [...COUNTRIES, [status.allowedCountry, status.allowedCountry] as [string, string]];

  return (
    <section className="hero" data-state={status.state} aria-live="polite">
      <Dial state={status.state} />
      <div className="hero-body">
        <h2 className="hero-title">{HEADLINE[status.state]}</h2>
        <p className="hero-message">{status.message}</p>
        {status.blockError && <p className="block-error">{status.blockError}</p>}
        <dl className="facts">
          <div>
            <dt>出口 IP</dt>
            <dd className="mono">{status.publicIp ?? "—"}</dd>
          </div>
          <div>
            <dt>出口国家</dt>
            <dd>{countryLabel}</dd>
          </div>
          <div>
            <dt>允许的出口国家</dt>
            <dd>
              <select
                className="select"
                value={status.allowedCountry}
                onChange={(e) => onCountryChange(e.target.value)}
              >
                {options.map(([c, n]) => (
                  <option key={c} value={c}>{n}（{c}）</option>
                ))}
              </select>
            </dd>
          </div>
          <div>
            <dt>检测节奏</dt>
            <dd>每 {status.intervalSeconds} 秒 · 上次 {clock(status.checkedAt)}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}

function SpoofStrip({ status }: { status: GuardStatus }) {
  const { spoofReady, spoofTimezone, stableStreak, stableNeeded } = status;
  let tone = "wait";
  let text: string;
  if (spoofReady && spoofTimezone) {
    tone = "ok";
    text = `时区伪装就绪：目标程序将以 ${spoofTimezone} 启动，与出口 IP 一致`;
  } else if (status.state === "protected") {
    text = `等待出口稳定 ${Math.min(stableStreak, stableNeeded)}/${stableNeeded}：同一 IP 连续检测通过后才允许带时区启动`;
  } else {
    tone = "off";
    text = "出口不在允许范围或无法确认，暂不允许带时区启动";
  }
  return (
    <div className="spoof-strip" data-tone={tone}>
      <span className="rule-dot" aria-hidden="true" />
      <span>{text}</span>
    </div>
  );
}

function TargetItem({
  row,
  status,
  actions,
}: {
  row: TargetRow;
  status: GuardStatus;
  actions: TargetActions;
}) {
  const launch = status.launches.find((l) => l.path.toLowerCase() === row.path.toLowerCase());
  const stale = !!launch && !!status.spoofTimezone && launch.timezone !== status.spoofTimezone;
  const canLaunch = row.spoof && status.spoofReady;
  return (
    <li>
      <div className="target-line">
        <b>{row.name}</b>
        <span className="tags">
          {row.builtin && <span className="tag">内置</span>}
          {row.running && <span className="tag tag-live">运行中</span>}
          {launch && !stale && <span className="tag tag-live">已用 {launch.timezone} 启动</span>}
          {stale && <span className="tag tag-warn">出口已变，需重启</span>}
        </span>
      </div>
      <span className="path mono" title={row.path}>{row.path}</span>
      <div className="target-ctl">
        {row.builtin ? (
          <span className="muted">防火墙阻断：始终开启</span>
        ) : (
          <>
            <label className="check">
              <input
                type="checkbox"
                checked={row.guard}
                onChange={(e) => actions.setFlags(row.path, e.target.checked, row.spoof)}
              />
              断网时阻断
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={row.spoof}
                onChange={(e) => actions.setFlags(row.path, row.guard, e.target.checked)}
              />
              时区伪装启动
            </label>
          </>
        )}
        <span className="ctl-gap" />
        <button
          className="btn btn-small"
          type="button"
          disabled={!canLaunch}
          title={canLaunch ? "" : "需要开启时区伪装，且出口稳定在允许国家"}
          onClick={() => actions.launch(row.path)}
        >
          {status.spoofTimezone ? `以 ${status.spoofTimezone} 启动` : "带时区启动"}
        </button>
        {!row.builtin && (
          <button className="btn btn-small btn-quiet" type="button" onClick={() => actions.remove(row.path)}>
            移除
          </button>
        )}
      </div>
    </li>
  );
}

function AddTarget({ status, actions }: { status: GuardStatus; actions: TargetActions }) {
  const [path, setPath] = useState("");
  const [guard, setGuard] = useState(true);
  const [spoof, setSpoof] = useState(true);
  const [procs, setProcs] = useState<TargetProcess[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");

  async function browse() {
    const picked = await actions.pickFile();
    if (picked) setPath(picked);
  }

  async function submit() {
    if (await actions.add(path, guard, spoof)) setPath("");
  }

  async function toggleProcs() {
    if (procs) {
      setProcs(null);
      return;
    }
    setLoading(true);
    setProcs(await actions.listProcesses());
    setLoading(false);
  }

  const registered = new Set(status.targets.map((t) => t.path.toLowerCase()));
  const q = filter.trim().toLowerCase();
  const shown = (procs ?? []).filter(
    (p) => !registered.has(p.path.toLowerCase()) && (!q || `${p.name} ${p.path}`.toLowerCase().includes(q)),
  );

  return (
    <div className="add-target">
      <div className="add-row">
        <input
          className="input mono"
          value={path}
          placeholder="程序完整路径，例如 C:\Tools\app.exe"
          spellCheck={false}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <button className="btn" type="button" onClick={browse}>浏览…</button>
        <button className="btn btn-primary" type="button" onClick={submit} disabled={!path.trim()}>
          添加
        </button>
      </div>
      <div className="add-row add-opts">
        <label className="check">
          <input type="checkbox" checked={guard} onChange={(e) => setGuard(e.target.checked)} />
          断网时阻断
        </label>
        <label className="check">
          <input type="checkbox" checked={spoof} onChange={(e) => setSpoof(e.target.checked)} />
          时区伪装启动
        </label>
        <span className="ctl-gap" />
        <button className="btn btn-small" type="button" onClick={toggleProcs} disabled={loading}>
          {loading ? "读取中…" : procs ? "收起进程列表" : "从运行中的进程选择"}
        </button>
      </div>

      {procs && (
        <div className="proc-pick">
          <input
            className="input"
            value={filter}
            placeholder="按名称或路径筛选"
            onChange={(e) => setFilter(e.target.value)}
          />
          {shown.length === 0 ? (
            <p className="empty">没有可添加的运行中程序。</p>
          ) : (
            <ul className="proc-list">
              {shown.slice(0, 60).map((p) => (
                <li key={p.path}>
                  <button type="button" className="proc-item" onClick={() => setPath(p.path)} title={p.path}>
                    <b>{p.name}</b>
                    <span className="path mono">{p.path}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function Targets({ status, actions }: { status: GuardStatus; actions: TargetActions }) {
  const rows = status.targets;
  const guarded = rows.filter((r) => r.guard).length;
  const tone = status.blocked ? "block" : guarded > 0 ? "ok" : "idle";
  const toneText = status.blocked
    ? "阻断规则已生效"
    : guarded > 0
      ? "未阻断"
      : "尚未登记程序路径";

  return (
    <section className="panel" aria-labelledby="targets-title">
      <div className="panel-head">
        <h3 id="targets-title" className="panel-title">目标程序</h3>
        <span className="muted">内置 codex.exe · claude.exe，可自行添加</span>
      </div>

      <SpoofStrip status={status} />

      {rows.length === 0 ? (
        <p className="empty">还没有目标程序。启动一次 Codex / Claude 会自动登记，也可以在下方添加任意程序。</p>
      ) : (
        <ul className="targets">
          {rows.map((r) => (
            <TargetItem key={r.path} row={r} status={status} actions={actions} />
          ))}
        </ul>
      )}

      <div className="rule-line" data-tone={tone}>
        <span className="rule-dot" aria-hidden="true" />
        <span>{toneText}</span>
        <span className="muted">阻断 {guarded} 个 · 共 {rows.length} 个程序</span>
      </div>

      <AddTarget status={status} actions={actions} />
    </section>
  );
}

function Events({ logs }: { logs: LogEntry[] }) {
  return (
    <section className="panel" aria-labelledby="events-title">
      <div className="panel-head">
        <h3 id="events-title" className="panel-title">事件</h3>
        <span className="muted">最近 30 条</span>
      </div>
      {logs.length === 0 ? (
        <p className="empty">还没有事件。守护开始检测后，状态变化会记录在这里。</p>
      ) : (
        <ol className="events">
          {logs.slice(0, 30).map((l, i) => (
            <li key={`${l.time}-${i}`} className={`ev ev-${l.level}`}>
              <time className="mono">{clock(l.time)}</time>
              <span className="ev-msg">{l.message}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

export function Dashboard({ status, error, busy, onCountryChange, onCheckNow, actions }: Props) {
  return (
    <div className="app" data-state={status.state}>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">ProxyGuard</span>
          <span className="brand-ver mono">0.5.0</span>
        </div>
        <button className="btn" type="button" onClick={onCheckNow} disabled={busy}>
          {busy ? "检测中…" : "立即检测"}
        </button>
      </header>

      {error && <p className="notice" role="alert">{error}</p>}

      <Hero status={status} onCountryChange={onCountryChange} />

      <div className="stack">
        <Targets status={status} actions={actions} />
        <Events logs={status.logs} />
      </div>

      <footer className="foot">
        守护随登录自动运行，关闭窗口后在托盘中继续。阻断依靠 Windows 防火墙规则，安装时的管理员授权即用于此。时区伪装只作用于通过 ProxyGuard 启动的进程，不修改系统时区，也不改变真实出口 IP。
      </footer>
    </div>
  );
}
