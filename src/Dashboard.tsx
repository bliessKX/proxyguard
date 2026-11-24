import type { CSSProperties } from "react";
import type { GuardState, GuardStatus, LogEntry } from "./types";

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

function Targets({ status }: { status: GuardStatus }) {
  const count = status.knownPaths.length;
  const tone = status.blocked ? "block" : count > 0 ? "ok" : "idle";
  const toneText = status.blocked
    ? "阻断规则已生效"
    : count > 0
      ? "未阻断"
      : "尚未登记程序路径";

  return (
    <section className="panel" aria-labelledby="targets-title">
      <div className="panel-head">
        <h3 id="targets-title" className="panel-title">目标程序</h3>
        <span className="muted">codex.exe · claude.exe</span>
      </div>

      {status.running.length === 0 ? (
        <p className="empty">没有运行中的 Codex 或 Claude。</p>
      ) : (
        <ul className="targets">
          {status.running.map((t) => (
            <li key={t.path}>
              <div className="target-line">
                <b>{t.name}.exe</b>
                <span className="tag tag-live">运行中</span>
              </div>
              <span className="path mono" title={t.path}>{t.path}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="rule-line" data-tone={tone}>
        <span className="rule-dot" aria-hidden="true" />
        <span>{toneText}</span>
        <span className="muted">已登记 {count} 个路径</span>
      </div>

      {count > 0 && (
        <details className="known">
          <summary>查看已登记路径</summary>
          <ul>
            {status.knownPaths.map((p) => (
              <li key={p} className="mono">{p}</li>
            ))}
          </ul>
        </details>
      )}
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

export function Dashboard({ status, error, busy, onCountryChange, onCheckNow }: Props) {
  return (
    <div className="app" data-state={status.state}>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">ProxyGuard</span>
          <span className="brand-ver mono">0.4.0</span>
        </div>
        <button className="btn" type="button" onClick={onCheckNow} disabled={busy}>
          {busy ? "检测中…" : "立即检测"}
        </button>
      </header>

      {error && <p className="notice" role="alert">{error}</p>}

      <Hero status={status} onCountryChange={onCountryChange} />

      <div className="columns">
        <Targets status={status} />
        <Events logs={status.logs} />
      </div>

      <footer className="foot">
        守护随登录自动运行，关闭窗口后在托盘中继续。阻断依靠 Windows 防火墙规则，安装时的管理员授权即用于此。
      </footer>
    </div>
  );
}
