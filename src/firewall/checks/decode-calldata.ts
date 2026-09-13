import {
  decodeAbiParameters,
  parseAbiParameters,
  toFunctionSelector,
} from "viem";

/**
 * Calldata decoding.
 *
 * The agent tells Arx what it is doing; the calldata is what it is actually
 * doing. Every check that matters downstream — who really receives the money,
 * how much allowance is being handed out, what a batch wrapper is hiding — is
 * derived from this decode and never from the intent.
 */

export type DecodedCallKind =
  | "NATIVE_TRANSFER"
  | "CONTRACT_CREATION"
  | "ERC20_TRANSFER"
  | "ERC20_TRANSFER_FROM"
  | "ERC20_APPROVE"
  | "ERC20_INCREASE_ALLOWANCE"
  | "ERC20_PERMIT"
  | "ERC721_SAFE_TRANSFER_FROM"
  | "ERC721_SET_APPROVAL_FOR_ALL"
  | "BATCH"
  | "UNKNOWN";

export type DecodedCall = {
  kind: DecodedCallKind;
  /**
   * Whether the arguments were fully understood. A batch whose inner payloads
   * could not be enumerated is `decoded: false` even though its selector is
   * known — a wrapper Arx cannot see inside is not a wrapper Arx can clear.
   */
  decoded: boolean;
  selector?: string;
  /** Canonical signature, e.g. `transfer(address,uint256)`. */
  signature?: string;
  /** The contract this particular call targets. Set on inner batch calls. */
  target?: string;
  /**
   * Everyone who ends up holding value or authority because of this call. This
   * is the set the recipient policy must be applied to — for an ERC-20
   * `transfer`, the transaction's `to` is the token, and the real payee is in
   * here.
   */
  recipients: string[];
  /** Address granted an allowance, if this call grants one. */
  spender?: string;
  /** Transferred amount in the token's base units, as a decimal string. */
  amount?: string;
  /** Allowance granted in base units, as a decimal string. */
  allowance?: string;
  tokenId?: string;
  args?: Record<string, string>;
  inner?: DecodedCall[];
  /** Why a decode failed, for the audit record. */
  note?: string;
};

/** `uint256` max: the canonical "infinite allowance" value. */
export const UINT256_MAX = 2n ** 256n - 1n;

type Handler = (payload: `0x${string}`, target?: string) => DecodedCall;

type Registration = {
  signature: string;
  kind: DecodedCallKind;
  handler: Handler;
};

const MAX_BATCH_DEPTH = 4;
/** Calldata bombs are cheap to write and expensive to walk. */
const MAX_INNER_CALLS = 64;

function base(
  signature: string,
  kind: DecodedCallKind,
  target?: string,
): DecodedCall {
  return {
    kind,
    decoded: true,
    selector: selectorOf(signature),
    signature,
    ...(target === undefined ? {} : { target }),
    recipients: [],
  };
}

function selectorOf(signature: string): string {
  return toFunctionSelector(signature as `${string}(${string})`);
}

function decodeArgs<T extends readonly unknown[]>(
  types: string,
  payload: `0x${string}`,
): T {
  return decodeAbiParameters(
    parseAbiParameters(types),
    payload,
  ) as unknown as T;
}

function lower(address: string): string {
  return address.toLowerCase();
}

/**
 * The signatures Arx understands.
 *
 * Selectors are computed from these strings at module load rather than written
 * as hex literals, so a typo becomes impossible: a wrong 4-byte constant would
 * silently misclassify calldata, which is exactly the kind of bug a firewall
 * cannot afford.
 */
const REGISTRATIONS: Registration[] = [
  {
    signature: "transfer(address,uint256)",
    kind: "ERC20_TRANSFER",
    handler: (payload, target) => {
      const [to, amount] = decodeArgs<[string, bigint]>(
        "address,uint256",
        payload,
      );
      const call = base("transfer(address,uint256)", "ERC20_TRANSFER", target);
      call.recipients = [lower(to)];
      call.amount = amount.toString();
      call.args = { to: lower(to), amount: amount.toString() };
      return call;
    },
  },
  {
    signature: "transferFrom(address,address,uint256)",
    kind: "ERC20_TRANSFER_FROM",
    handler: (payload, target) => {
      const [from, to, amount] = decodeArgs<[string, string, bigint]>(
        "address,address,uint256",
        payload,
      );
      const call = base(
        "transferFrom(address,address,uint256)",
        "ERC20_TRANSFER_FROM",
        target,
      );
      call.recipients = [lower(to)];
      call.amount = amount.toString();
      call.args = {
        from: lower(from),
        to: lower(to),
        amount: amount.toString(),
      };
      return call;
    },
  },
  {
    signature: "approve(address,uint256)",
    kind: "ERC20_APPROVE",
    handler: (payload, target) => {
      const [spender, amount] = decodeArgs<[string, bigint]>(
        "address,uint256",
        payload,
      );
      const call = base("approve(address,uint256)", "ERC20_APPROVE", target);
      // A spender is a recipient of authority over the balance, so the
      // recipient policy applies to it exactly as it does to a payee.
      call.recipients = [lower(spender)];
      call.spender = lower(spender);
      call.allowance = amount.toString();
      call.args = { spender: lower(spender), allowance: amount.toString() };
      return call;
    },
  },
  {
    signature: "increaseAllowance(address,uint256)",
    kind: "ERC20_INCREASE_ALLOWANCE",
    handler: (payload, target) => {
      const [spender, amount] = decodeArgs<[string, bigint]>(
        "address,uint256",
        payload,
      );
      const call = base(
        "increaseAllowance(address,uint256)",
        "ERC20_INCREASE_ALLOWANCE",
        target,
      );
      call.recipients = [lower(spender)];
      call.spender = lower(spender);
      call.allowance = amount.toString();
      call.args = { spender: lower(spender), increaseBy: amount.toString() };
      return call;
    },
  },
  {
    // EIP-2612.
    signature: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    kind: "ERC20_PERMIT",
    handler: (payload, target) => {
      const [owner, spender, value, deadline] = decodeArgs<
        [string, string, bigint, bigint]
      >("address,address,uint256,uint256,uint8,bytes32,bytes32", payload);
      const call = base(
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "ERC20_PERMIT",
        target,
      );
      call.recipients = [lower(spender)];
      call.spender = lower(spender);
      call.allowance = value.toString();
      call.args = {
        owner: lower(owner),
        spender: lower(spender),
        value: value.toString(),
        deadline: deadline.toString(),
      };
      return call;
    },
  },
  {
    signature: "safeTransferFrom(address,address,uint256)",
    kind: "ERC721_SAFE_TRANSFER_FROM",
    handler: (payload, target) => {
      const [from, to, tokenId] = decodeArgs<[string, string, bigint]>(
        "address,address,uint256",
        payload,
      );
      const call = base(
        "safeTransferFrom(address,address,uint256)",
        "ERC721_SAFE_TRANSFER_FROM",
        target,
      );
      call.recipients = [lower(to)];
      call.tokenId = tokenId.toString();
      call.args = {
        from: lower(from),
        to: lower(to),
        tokenId: tokenId.toString(),
      };
      return call;
    },
  },
  {
    signature: "safeTransferFrom(address,address,uint256,bytes)",
    kind: "ERC721_SAFE_TRANSFER_FROM",
    handler: (payload, target) => {
      const [from, to, tokenId] = decodeArgs<[string, string, bigint, string]>(
        "address,address,uint256,bytes",
        payload,
      );
      const call = base(
        "safeTransferFrom(address,address,uint256,bytes)",
        "ERC721_SAFE_TRANSFER_FROM",
        target,
      );
      call.recipients = [lower(to)];
      call.tokenId = tokenId.toString();
      call.args = {
        from: lower(from),
        to: lower(to),
        tokenId: tokenId.toString(),
      };
      return call;
    },
  },
  {
    signature: "setApprovalForAll(address,bool)",
    kind: "ERC721_SET_APPROVAL_FOR_ALL",
    handler: (payload, target) => {
      const [operator, approved] = decodeArgs<[string, boolean]>(
        "address,bool",
        payload,
      );
      const call = base(
        "setApprovalForAll(address,bool)",
        "ERC721_SET_APPROVAL_FOR_ALL",
        target,
      );
      call.recipients = approved ? [lower(operator)] : [];
      call.spender = lower(operator);
      // Blanket operator authority over an entire collection has no numeric
      // amount, so it is scored as an unlimited grant.
      call.allowance = approved ? UINT256_MAX.toString() : "0";
      call.args = { operator: lower(operator), approved: String(approved) };
      return call;
    },
  },
];

const BY_SELECTOR = new Map<string, Registration>();

for (const registration of REGISTRATIONS) {
  BY_SELECTOR.set(selectorOf(registration.signature), registration);
}

/** Canonical signature for a selector, when Arx knows it. */
export function signatureForSelector(selector: string): string | undefined {
  return BY_SELECTOR.get(selector.toLowerCase())?.signature;
}

export function selectorForSignature(signature: string): string | undefined {
  try {
    return selectorOf(signature);
  } catch {
    return undefined;
  }
}

/**
 * Batch wrappers.
 *
 * `inner` extracts the nested payloads. Each entry says which contract the
 * inner call hits: the `multicall` family re-enters the same contract, while
 * the Multicall3 `aggregate` family carries an explicit target per call — and
 * that target must go through the contract policy too, or a single allowlisted
 * multicall address becomes a universal proxy.
 */
type BatchRegistration = {
  signature: string;
  /** `undefined` means Arx cannot enumerate the inner calls. */
  inner?: (
    payload: `0x${string}`,
    outerTarget?: string,
  ) => Array<{ target?: string; data: string }>;
  note?: string;
};

const BATCH_REGISTRATIONS: BatchRegistration[] = [
  {
    signature: "multicall(bytes[])",
    inner: (payload, outerTarget) => {
      const [calls] = decodeArgs<[readonly string[]]>("bytes[]", payload);
      return calls.map((data) => ({ target: outerTarget, data }));
    },
  },
  {
    signature: "multicall(uint256,bytes[])",
    inner: (payload, outerTarget) => {
      const [, calls] = decodeArgs<[bigint, readonly string[]]>(
        "uint256,bytes[]",
        payload,
      );
      return calls.map((data) => ({ target: outerTarget, data }));
    },
  },
  {
    signature: "multicall(bytes32,bytes[])",
    inner: (payload, outerTarget) => {
      const [, calls] = decodeArgs<[string, readonly string[]]>(
        "bytes32,bytes[]",
        payload,
      );
      return calls.map((data) => ({ target: outerTarget, data }));
    },
  },
  {
    // Multicall / Multicall3 `aggregate(Call[])`, Call = (target, callData).
    signature: "aggregate((address,bytes)[])",
    inner: (payload) => {
      const [calls] = decodeArgs<[readonly [string, string][]]>(
        "(address,bytes)[]",
        payload,
      );
      return calls.map(([target, data]) => ({ target: lower(target), data }));
    },
  },
  {
    // Multicall3 `aggregate3(Call3[])`, Call3 = (target, allowFailure, callData).
    signature: "aggregate3((address,bool,bytes)[])",
    inner: (payload) => {
      const [calls] = decodeArgs<[readonly [string, boolean, string][]]>(
        "(address,bool,bytes)[]",
        payload,
      );
      return calls.map(([target, , data]) => ({ target: lower(target), data }));
    },
  },
  {
    // Multicall3 `aggregate3Value(Call3Value[])`.
    signature: "aggregate3Value((address,bool,uint256,bytes)[])",
    inner: (payload) => {
      const [calls] = decodeArgs<
        [readonly [string, boolean, bigint, string][]]
      >("(address,bool,uint256,bytes)[]", payload);
      return calls.map(([target, , , data]) => ({
        target: lower(target),
        data,
      }));
    },
  },
  {
    signature: "tryAggregate(bool,(address,bytes)[])",
    inner: (payload) => {
      const [, calls] = decodeArgs<[boolean, readonly [string, string][]]>(
        "bool,(address,bytes)[]",
        payload,
      );
      return calls.map(([target, data]) => ({ target: lower(target), data }));
    },
  },
  {
    // Uniswap Universal Router. The `bytes[]` are per-command ABI-encoded
    // parameters, not nested calldata, so there is nothing to recurse into and
    // Arx refuses to pretend otherwise.
    signature: "execute(bytes,bytes[])",
    note: "Universal Router command stream is not decodable as nested calls",
  },
  {
    signature: "execute(bytes,bytes[],uint256)",
    note: "Universal Router command stream is not decodable as nested calls",
  },
];

const BATCH_BY_SELECTOR = new Map<string, BatchRegistration>();

for (const registration of BATCH_REGISTRATIONS) {
  BATCH_BY_SELECTOR.set(selectorOf(registration.signature), registration);
}

export function isBatchSelector(selector: string): boolean {
  return BATCH_BY_SELECTOR.has(selector.toLowerCase());
}

export type DecodeInput = {
  /** Absent means contract creation. */
  to?: string;
  data: string;
  /** Native value in wei, decimal string. Used only to tell a bare transfer apart. */
  value?: string;
};

export function decodeCalldata(input: DecodeInput): DecodedCall {
  return decodeInternal(
    { target: input.to, data: input.data, value: input.value },
    0,
  );
}

function decodeInternal(
  input: { target?: string; data: string; value?: string },
  depth: number,
): DecodedCall {
  if (input.target === undefined) {
    return {
      kind: "CONTRACT_CREATION",
      decoded: true,
      recipients: [],
    };
  }

  const data = input.data.toLowerCase();

  if (data === "" || data === "0x") {
    return {
      kind: "NATIVE_TRANSFER",
      decoded: true,
      target: lower(input.target),
      recipients: [lower(input.target)],
      ...(input.value === undefined ? {} : { amount: input.value }),
    };
  }

  // Fewer than 4 bytes of calldata cannot name a function; it is neither a
  // plain transfer nor a call Arx can reason about.
  if (data.length < 10) {
    return {
      kind: "UNKNOWN",
      decoded: false,
      target: lower(input.target),
      recipients: [],
      note: "Calldata is shorter than a 4-byte selector",
    };
  }

  const selector = data.slice(0, 10);
  const payload = `0x${data.slice(10)}` as `0x${string}`;

  const registration = BY_SELECTOR.get(selector);

  if (registration) {
    try {
      return registration.handler(payload, lower(input.target));
    } catch (error) {
      return {
        kind: "UNKNOWN",
        decoded: false,
        selector,
        signature: registration.signature,
        target: lower(input.target),
        recipients: [],
        note: `Arguments for ${registration.signature} failed to decode: ${
          error instanceof Error ? error.message : String(error)
        }`,
      };
    }
  }

  const batch = BATCH_BY_SELECTOR.get(selector);

  if (batch) {
    return decodeBatch(batch, selector, payload, lower(input.target), depth);
  }

  return {
    kind: "UNKNOWN",
    decoded: false,
    selector,
    target: lower(input.target),
    recipients: [],
    note: "Selector is not in Arx's decoder registry",
  };
}

function decodeBatch(
  batch: BatchRegistration,
  selector: string,
  payload: `0x${string}`,
  target: string,
  depth: number,
): DecodedCall {
  const call: DecodedCall = {
    kind: "BATCH",
    decoded: false,
    selector,
    signature: batch.signature,
    target,
    recipients: [],
    inner: [],
  };

  if (!batch.inner) {
    call.note = batch.note ?? "Batch contents are not enumerable";
    return call;
  }

  if (depth >= MAX_BATCH_DEPTH) {
    call.note = `Batch nesting exceeds the maximum depth of ${MAX_BATCH_DEPTH}`;
    return call;
  }

  let entries: Array<{ target?: string; data: string }>;

  try {
    entries = batch.inner(payload, target);
  } catch (error) {
    call.note = `Batch payload failed to decode: ${
      error instanceof Error ? error.message : String(error)
    }`;
    return call;
  }

  if (entries.length > MAX_INNER_CALLS) {
    call.note = `Batch contains ${entries.length} calls, above the limit of ${MAX_INNER_CALLS}`;
    return call;
  }

  const inner = entries.map((entry) =>
    decodeInternal({ target: entry.target, data: entry.data }, depth + 1),
  );

  call.inner = inner;
  // The wrapper is only "decoded" when every leaf it contains is, so an
  // unreadable inner call cannot be laundered through a readable wrapper.
  call.decoded = inner.every((child) => child.decoded);
  call.recipients = dedupe(inner.flatMap((child) => child.recipients));

  if (!call.decoded) {
    call.note = "At least one inner call could not be decoded";
  }

  return call;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

/** Depth-first walk over a call and everything nested inside it. */
export function flattenCall(call: DecodedCall): DecodedCall[] {
  const flat: DecodedCall[] = [call];

  for (const child of call.inner ?? []) {
    flat.push(...flattenCall(child));
  }

  return flat;
}
