/**
 * Terminal presentation for the demo suite.
 *
 * The demo is watched, not read: a judge sees this output in a screen recording
 * once and forms an opinion. So width is fixed, labels are column-aligned, and
 * colour carries meaning (green allow, red deny, amber escalate) rather than
 * decoration. ASCII and box-drawing only — no emoji, which render
 * inconsistently across terminals and recordings.
 */

const ENV_NO_COLOR =
  process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== "";

let colorEnabled = !ENV_NO_COLOR;

export function setColorEnabled(enabled: boolean): void {
  colorEnabled = enabled && !ENV_NO_COLOR;
}

export const WIDTH = 78;

function wrap(code: string, close: string) {
  return (text: string): string =>
    colorEnabled ? `${code}${text}${close}` : text;
}

export const style = {
  bold: wrap("[1m", "[22m"),
  dim: wrap("[2m", "[22m"),
  red: wrap("[31m", "[39m"),
  green: wrap("[32m", "[39m"),
  amber: wrap("[33m", "[39m"),
  blue: wrap("[34m", "[39m"),
  magenta: wrap("[35m", "[39m"),
  cyan: wrap("[36m", "[39m"),
  grey: wrap("[90m", "[39m"),
  inverse: wrap("[7m", "[27m"),
};

/** Visible length, ignoring ANSI escapes, so padding stays correct in colour. */
export function visibleLength(text: string): number {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\[[0-9;]*m/g, "").length;
}

export function pad(text: string, width: number): string {
  const missing = width - visibleLength(text);
  return missing > 0 ? text + " ".repeat(missing) : text;
}

export function write(line = ""): void {
  process.stdout.write(`${line}\n`);
}

export function rule(char = "─"): void {
  write(style.grey(char.repeat(WIDTH)));
}

export function banner(title: string, subtitle?: string): void {
  write();
  write(style.cyan(`┌${"─".repeat(WIDTH - 2)}┐`));
  write(
    `${style.cyan("│")} ${pad(style.bold(title), WIDTH - 4)} ${style.cyan("│")}`,
  );

  if (subtitle) {
    write(
      `${style.cyan("│")} ${pad(style.grey(subtitle), WIDTH - 4)} ${style.cyan("│")}`,
    );
  }

  write(style.cyan(`└${"─".repeat(WIDTH - 2)}┘`));
}

const LABEL_WIDTH = 9;

/** `LABEL   value` with continuation lines aligned under the value column. */
export function field(label: string, value: string | string[]): void {
  const lines = Array.isArray(value) ? value : [value];
  const head = pad(style.grey(label.toUpperCase()), LABEL_WIDTH);

  lines.forEach((line, index) => {
    write(`${index === 0 ? head : " ".repeat(LABEL_WIDTH)} ${line}`);
  });
}

/** Two-column key/value block used for request and transaction detail. */
export function kv(pairs: Array<[string, string]>, indent = 2): number {
  const keyWidth = pairs.reduce(
    (widest, [key]) => Math.max(widest, key.length),
    0,
  );

  for (const [key, value] of pairs) {
    write(
      `${" ".repeat(LABEL_WIDTH + indent)}${style.grey(pad(key, keyWidth))}  ${value}`,
    );
  }

  return pairs.length;
}

export function decisionBadge(decision: string | null): string {
  switch (decision) {
    case "ALLOW":
      return style.green(style.bold(" ALLOW "));
    case "ESCALATE":
      return style.amber(style.bold(" ESCALATE "));
    case "DENY":
      return style.red(style.bold(" DENY "));
    default:
      return style.grey(" ? ");
  }
}

export function statusBadge(status: string): string {
  switch (status) {
    case "PASS":
      return style.green(style.bold("PASS"));
    case "FAIL":
      return style.red(style.bold("FAIL"));
    case "BLOCKED":
      return style.amber(style.bold("BLOCKED"));
    case "SKIP":
      return style.grey(style.bold("SKIP"));
    default:
      return status;
  }
}

/** Shortens a hex string for display without hiding the poisoning-relevant ends. */
export function shortHex(value: string, keep = 6): string {
  if (!value.startsWith("0x") || value.length <= keep * 2 + 4) {
    return value;
  }

  return `${value.slice(0, 2 + keep)}…${value.slice(-keep)}`;
}

export function formatWei(wei: string): string {
  try {
    const value = BigInt(wei);
    const whole = value / 10n ** 18n;
    const fraction = (value % 10n ** 18n).toString().padStart(18, "0");

    return `${whole}.${fraction.slice(0, 6)} ETH`;
  } catch {
    return `${wei} wei`;
  }
}

export function formatUsd(amount: number | null | undefined): string {
  if (amount === null || amount === undefined || !Number.isFinite(amount)) {
    return "n/a";
  }

  return `$${amount.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
