/**
 * ERC-7730 style clear-signing support.
 *
 * Clear signing is the difference between a device asking a human to approve
 * `0xa9059cbb000...` and asking them to approve "Send 25 USDT to 0xAlice…".
 * Blind approval of opaque calldata is the failure mode this whole project
 * exists to remove, so the descriptor format Arx follows is the real one:
 *
 * Specification: https://github.com/LedgerHQ/clear-signing-erc7730-registry/blob/master/specs/erc-7730.md
 * v2 JSON schema: https://github.com/LedgerHQ/clear-signing-erc7730-registry/blob/master/specs/erc7730-v2.schema.json
 * Registry:      https://github.com/LedgerHQ/clear-signing-erc7730-registry/tree/master/registry
 *
 * `renderDeviceScreens()` is a *prediction* of what a device would display,
 * computed locally by Arx. It is not, and must never be presented as, evidence
 * of what a device actually showed — that is `SpeculosControl.readDeviceScreens()`
 * in `speculos-control.ts`. Both appear in the signer result, separately
 * labelled.
 */

import {
  decodeFunctionData,
  formatUnits,
  getAddress,
  keccak256,
  parseAbi,
  toFunctionSelector,
  type Abi,
  type Hex,
} from "viem";

import type { EvmTransaction } from "../types/transaction";

// --- Descriptor model (ERC-7730 v2 subset Arx consumes) --------------------

/**
 * Field formats from the specification's "Field formats" reference. Arx renders
 * the subset it can render honestly; anything else falls through to `raw`.
 */
export type Erc7730FieldFormat =
  | "raw"
  | "amount"
  | "tokenAmount"
  | "nftName"
  | "date"
  | "duration"
  | "unit"
  | "addressName"
  | "enum"
  | "calldata";

export type Erc7730Field = {
  /** Path reference: `#.` = decoded calldata, `@.` = the transaction container. */
  path: string;
  label: string;
  format: Erc7730FieldFormat;
  params?: Record<string, unknown>;
};

export type Erc7730Format = {
  /** The verb the device leads with, e.g. "Send" or "Approve". */
  intent: string;
  fields: Erc7730Field[];
  required?: string[];
};

export type Erc7730Deployment = {
  chainId: number;
  address: string;
};

export type Erc7730Descriptor = {
  $schema?: string;
  context: {
    $id?: string;
    contract: {
      deployments: Erc7730Deployment[];
    };
  };
  metadata: {
    owner?: string;
    contractName?: string;
    info?: {
      url?: string;
      legalName?: string;
      deploymentDate?: string;
    };
    token?: {
      ticker: string;
      name?: string;
      decimals: number;
    };
  };
  /** Keyed by the full function signature, exactly as the registry keys them. */
  display: {
    formats: Record<string, Erc7730Format>;
  };
  /** Arx annotation: where this descriptor came from. Never part of ERC-7730. */
  arxSource?: string;
};

// --- Bundled descriptors ---------------------------------------------------

/**
 * Tether USD, copied verbatim from the public registry (including its
 * 6-decimal token metadata and the `approve` threshold that renders an
 * effectively-unlimited allowance as "Unlimited").
 *
 * https://github.com/LedgerHQ/clear-signing-erc7730-registry/blob/master/registry/tether/calldata-usdt.json
 */
export const USDT_DESCRIPTOR: Erc7730Descriptor = {
  context: {
    $id: "Tether USD",
    contract: {
      deployments: [
        { chainId: 1, address: "0xdAC17F958D2ee523a2206206994597C13D831ec7" },
        { chainId: 137, address: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F" },
      ],
    },
  },
  metadata: {
    owner: "Tether Limited",
    contractName: "Tether USD",
    info: {
      url: "https://tether.to/",
      deploymentDate: "2017-11-28T12:41:21Z",
    },
    token: { ticker: "USDT", name: "Tether USD", decimals: 6 },
  },
  display: {
    formats: {
      "transfer(address _to, uint256 _value)": {
        intent: "Send",
        fields: [
          {
            path: "#._value",
            label: "Amount",
            format: "tokenAmount",
            params: { tokenPath: "@.to" },
          },
          {
            path: "#._to",
            label: "To",
            format: "addressName",
            params: { types: ["eoa"], sources: ["local", "ens"] },
          },
        ],
      },
      "approve(address _spender, uint256 _value)": {
        intent: "Approve",
        fields: [
          {
            path: "#._spender",
            label: "Spender",
            format: "addressName",
            params: { types: ["eoa", "contract"] },
          },
          {
            path: "#._value",
            label: "Amount",
            format: "tokenAmount",
            params: {
              tokenPath: "@.to",
              threshold:
                "0x8000000000000000000000000000000000000000000000000000000000000000",
            },
          },
        ],
      },
    },
  },
  arxSource:
    "LedgerHQ/clear-signing-erc7730-registry registry/tether/calldata-usdt.json",
};

/**
 * A template for any ERC-20, authored by Arx rather than taken from the
 * registry, with the same field shapes as the registry's token descriptors.
 *
 * `deployments` is empty on purpose. An empty allowlist permits nothing here
 * too: a descriptor with no deployments never matches a lookup, so this
 * template cannot silently claim to describe a contract nobody bound it to.
 * Bind it with `erc20DescriptorFor()`.
 */
export const ERC20_TEMPLATE_DESCRIPTOR: Erc7730Descriptor = {
  context: { $id: "ERC-20", contract: { deployments: [] } },
  metadata: { contractName: "ERC-20 token" },
  display: {
    formats: {
      "transfer(address to, uint256 value)": {
        intent: "Send",
        fields: [
          {
            path: "#.value",
            label: "Amount",
            format: "tokenAmount",
            params: { tokenPath: "@.to" },
          },
          {
            path: "#.to",
            label: "To",
            format: "addressName",
            params: { types: ["eoa"], sources: ["local", "ens"] },
          },
        ],
      },
      "approve(address spender, uint256 value)": {
        intent: "Approve",
        fields: [
          {
            path: "#.spender",
            label: "Spender",
            format: "addressName",
            params: { types: ["eoa", "contract"] },
          },
          {
            path: "#.value",
            label: "Amount",
            format: "tokenAmount",
            params: {
              tokenPath: "@.to",
              threshold:
                "0x8000000000000000000000000000000000000000000000000000000000000000",
            },
          },
        ],
      },
    },
  },
  arxSource: "arx:bundled ERC-20 template (not a registry entry)",
};

/** Binds the ERC-20 template to one concrete deployment. */
export function erc20DescriptorFor(token: {
  chainId: number;
  address: string;
  ticker: string;
  decimals: number;
  name?: string;
}): Erc7730Descriptor {
  return {
    ...ERC20_TEMPLATE_DESCRIPTOR,
    context: {
      $id: token.name ?? token.ticker,
      contract: {
        deployments: [{ chainId: token.chainId, address: token.address }],
      },
    },
    metadata: {
      contractName: token.name ?? token.ticker,
      token: {
        ticker: token.ticker,
        decimals: token.decimals,
        ...(token.name === undefined ? {} : { name: token.name }),
      },
    },
    arxSource: "arx:bundled ERC-20 template, bound by the operator",
  };
}

export const BUNDLED_DESCRIPTORS: readonly Erc7730Descriptor[] = [
  USDT_DESCRIPTOR,
];

/**
 * Finds a bundled descriptor for a contract.
 *
 * Matches on chain **and** address. A descriptor that names a different chain
 * does not describe this contract, and a near-match is exactly how a
 * clear-signing UI gets tricked into labelling the wrong token.
 */
export function findBundledDescriptor(
  chainId: number,
  address: string,
): Erc7730Descriptor | undefined {
  const target = address.toLowerCase();

  return BUNDLED_DESCRIPTORS.find((descriptor) =>
    descriptor.context.contract.deployments.some(
      (deployment) =>
        deployment.chainId === chainId &&
        deployment.address.toLowerCase() === target,
    ),
  );
}

// --- Calldata decoding -----------------------------------------------------

export type DecodedCallArg = {
  name: string;
  type: string;
  /** Stringified value: addresses checksummed, integers in decimal. */
  value: string;
};

export type DecodedCall = {
  selector: Hex;
  /** Canonical signature, e.g. `transfer(address,uint256)`. */
  signature?: string;
  functionName?: string;
  args: DecodedCallArg[];
};

const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 value) returns (bool)",
  "function approve(address spender, uint256 value) returns (bool)",
  "function transferFrom(address from, address to, uint256 value) returns (bool)",
]);

const ERC20_ARG_NAMES: Record<string, string[]> = {
  transfer: ["to", "value"],
  approve: ["spender", "value"],
  transferFrom: ["from", "to", "value"],
};

/** Extracts the 4-byte selector, or `undefined` when there is no calldata. */
export function calldataSelector(data: string): Hex | undefined {
  if (!data.startsWith("0x") || data.length < 10) {
    return undefined;
  }

  return data.slice(0, 10).toLowerCase() as Hex;
}

/**
 * Decodes ERC-20 `transfer`/`approve`/`transferFrom` calldata.
 *
 * Returns `undefined` rather than a guess when the calldata is not one of
 * those: an unrecognised call must reach the human as an unrecognised call.
 */
export function decodeErc20Call(data: string): DecodedCall | undefined {
  const selector = calldataSelector(data);

  if (selector === undefined) {
    return undefined;
  }

  try {
    const decoded = decodeFunctionData({
      abi: ERC20_ABI,
      data: data as Hex,
    });

    const names = ERC20_ARG_NAMES[decoded.functionName] ?? [];
    const values = (decoded.args ?? []) as readonly unknown[];

    return {
      selector,
      functionName: decoded.functionName,
      args: values.map((value, index) => ({
        name: names[index] ?? `arg${index}`,
        type: typeof value === "bigint" ? "uint256" : "address",
        value:
          typeof value === "bigint"
            ? value.toString(10)
            : getAddress(String(value)),
      })),
    };
  } catch {
    return undefined;
  }
}

/**
 * Decodes calldata against one explicit function signature.
 *
 * ERC-7730 keys each display format by the *full* signature, and its `#.`
 * paths refer to that signature's parameter names — the registry's USDT entry
 * uses `#._to` and `#._value`, for instance. So the descriptor, not a
 * hardcoded ABI, has to supply the names: decoding with our own ABI would
 * resolve `#._value` to nothing and silently render "(unavailable)" where an
 * amount belongs.
 */
export function decodeCallWithSignature(
  data: string,
  signature: string,
): DecodedCall | undefined {
  const selector = calldataSelector(data);

  if (selector === undefined) {
    return undefined;
  }

  try {
    const declaration = signature.startsWith("function ")
      ? signature
      : `function ${signature}`;

    // `parseAbi` infers a literal type it cannot compute for a runtime string,
    // so the result is widened to the nominal `Abi` before use.
    const abi = parseAbi([declaration] as [string]) as Abi;
    const item = abi[0];

    if (item === undefined || item.type !== "function") {
      return undefined;
    }

    const decoded = decodeFunctionData({ abi, data: data as Hex });
    const values = (decoded.args ?? []) as readonly unknown[];

    return {
      selector,
      signature,
      functionName: decoded.functionName,
      args: values.map((value, index) => {
        const input = item.inputs[index];

        return {
          name: input?.name ?? `arg${index}`,
          type: input?.type ?? typeof value,
          value: stringifyArg(value),
        };
      }),
    };
  } catch {
    return undefined;
  }
}

function stringifyArg(value: unknown): string {
  if (typeof value === "bigint") {
    return value.toString(10);
  }

  if (typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)) {
    return getAddress(value);
  }

  return String(value);
}

// --- Rendering -------------------------------------------------------------

export type RenderedField = {
  label: string;
  value: string;
  format: Erc7730FieldFormat | "container";
  /** The underlying value before formatting, when formatting hid something. */
  raw?: string;
  warning?: string;
};

export type RenderedDeviceScreens = {
  /**
   * Marks this as Arx's local prediction. The device's actual screens are
   * captured separately by `SpeculosControl.readDeviceScreens()`.
   */
  renderedBy: "arx-clear-signing-preview";
  /**
   * True only when every displayed field came from a descriptor bound to this
   * exact contract on this exact chain. False means the human is being asked
   * to approve something Arx could not decode — blind signing.
   */
  clearSigned: boolean;
  intent: string;
  fields: RenderedField[];
  /** `context.$id` of the descriptor used, when one was. */
  descriptorId?: string;
  descriptorSource?: string;
  warnings: string[];
};

const NATIVE_CURRENCY_DECIMALS = 18;

/**
 * Produces the human-readable field list a device would show.
 *
 * Three cases, in order:
 *   1. no calldata           → a native transfer, fully renderable on its own
 *   2. calldata + descriptor → the descriptor's intent and fields
 *   3. calldata, no match    → blind signing, stated as such
 */
export function renderDeviceScreens(
  transaction: EvmTransaction,
  decodedCall?: DecodedCall | null,
  descriptor?: Erc7730Descriptor,
): RenderedDeviceScreens {
  const warnings: string[] = [];
  const maxFees = formatNativeAmount(
    BigInt(transaction.gasLimit) * BigInt(transaction.maxFeePerGas),
  );

  const feeField: RenderedField = {
    label: "Max fees",
    value: maxFees,
    format: "amount",
    raw: (BigInt(transaction.gasLimit) * BigInt(transaction.maxFeePerGas)).toString(10),
  };

  const networkField: RenderedField = {
    label: "Network",
    value: describeChain(transaction.chainId),
    format: "container",
    raw: String(transaction.chainId),
  };

  // Case 1: a plain native-value transfer.
  if (transaction.data === "0x" || transaction.data.length <= 2) {
    if (transaction.to === undefined) {
      // Contract creation with no calldata is degenerate, but never silently
      // rendered as a send.
      return {
        renderedBy: "arx-clear-signing-preview",
        clearSigned: false,
        intent: "Deploy contract",
        fields: [
          { label: "Amount", value: formatNativeAmount(BigInt(transaction.value)), format: "amount" },
          feeField,
          networkField,
        ],
        warnings: ["Contract creation: the device cannot describe the deployed code"],
      };
    }

    return {
      renderedBy: "arx-clear-signing-preview",
      clearSigned: true,
      intent: "Send",
      fields: [
        {
          label: "Amount",
          value: formatNativeAmount(BigInt(transaction.value)),
          format: "amount",
          raw: transaction.value,
        },
        {
          label: "To",
          value: getAddress(transaction.to),
          format: "addressName",
        },
        feeField,
        networkField,
      ],
      warnings,
    };
  }

  const selector = calldataSelector(transaction.data);
  const call = decodedCall ?? decodeErc20Call(transaction.data);

  const chosen =
    descriptor ??
    (transaction.to === undefined
      ? undefined
      : findBundledDescriptor(transaction.chainId, transaction.to));

  if (chosen !== undefined && transaction.to !== undefined) {
    const bound = chosen.context.contract.deployments.some(
      (deployment) =>
        deployment.chainId === transaction.chainId &&
        deployment.address.toLowerCase() === transaction.to?.toLowerCase(),
    );

    if (!bound) {
      warnings.push(
        `Descriptor "${chosen.context.$id ?? "unnamed"}" is not bound to ${transaction.to} on chain ${transaction.chainId}; its labels are not trustworthy for this call`,
      );
    }

    const matched = matchFormat(chosen, selector);

    // Prefer the descriptor's own parameter names over anything Arx guessed.
    const resolvedCall =
      matched === undefined
        ? call
        : decodeCallWithSignature(transaction.data, matched.signature) ?? call;

    if (matched !== undefined && resolvedCall !== undefined) {
      const fields = matched.format.fields.map((field) =>
        renderField(field, resolvedCall, transaction, chosen),
      );

      return {
        renderedBy: "arx-clear-signing-preview",
        clearSigned: bound,
        intent: matched.format.intent,
        fields: [
          ...fields,
          {
            label: "Contract",
            value: getAddress(transaction.to),
            format: "addressName",
          },
          feeField,
          networkField,
        ],
        ...(chosen.context.$id === undefined
          ? {}
          : { descriptorId: chosen.context.$id }),
        ...(chosen.arxSource === undefined
          ? {}
          : { descriptorSource: chosen.arxSource }),
        warnings,
      };
    }

    warnings.push(
      matched === undefined
        ? `Descriptor has no format for selector ${selector ?? "(none)"}`
        : "Calldata could not be decoded against the descriptor's signature",
    );
  }

  // Case 3: blind signing. Say so plainly.
  return {
    renderedBy: "arx-clear-signing-preview",
    clearSigned: false,
    intent: "Blind sign",
    fields: [
      ...(transaction.to === undefined
        ? []
        : [
            {
              label: "Contract",
              value: getAddress(transaction.to),
              format: "addressName" as const,
            },
          ]),
      {
        label: "Selector",
        value: selector ?? "(none)",
        format: "raw",
      },
      {
        label: "Calldata",
        value: `${(transaction.data.length - 2) / 2} bytes, keccak ${keccak256(
          transaction.data as Hex,
        ).slice(0, 18)}…`,
        format: "raw",
        raw: transaction.data,
      },
      {
        label: "Amount",
        value: formatNativeAmount(BigInt(transaction.value)),
        format: "amount",
        raw: transaction.value,
      },
      feeField,
      networkField,
    ],
    warnings: [
      ...warnings,
      "No clear-signing descriptor matched: the human is being asked to approve undecoded calldata",
    ],
  };
}

function matchFormat(
  descriptor: Erc7730Descriptor,
  selector: Hex | undefined,
): { signature: string; format: Erc7730Format } | undefined {
  if (selector === undefined) {
    return undefined;
  }

  for (const [signature, format] of Object.entries(
    descriptor.display.formats,
  )) {
    let candidate: Hex;

    try {
      candidate = toFunctionSelector(signature);
    } catch {
      // A descriptor key we cannot parse is skipped rather than guessed at.
      continue;
    }

    if (candidate.toLowerCase() === selector.toLowerCase()) {
      return { signature, format };
    }
  }

  return undefined;
}

function renderField(
  field: Erc7730Field,
  call: DecodedCall,
  transaction: EvmTransaction,
  descriptor: Erc7730Descriptor,
): RenderedField {
  const resolved = resolvePath(field.path, call, transaction);

  if (resolved === undefined) {
    return {
      label: field.label,
      value: "(unavailable)",
      format: field.format,
      warning: `Path ${field.path} did not resolve`,
    };
  }

  switch (field.format) {
    case "tokenAmount": {
      const threshold = field.params?.["threshold"];

      if (typeof threshold === "string") {
        try {
          if (BigInt(resolved) >= BigInt(threshold)) {
            const message =
              typeof field.params?.["message"] === "string"
                ? (field.params["message"] as string)
                : "Unlimited";
            const ticker = descriptor.metadata.token?.ticker ?? "tokens";

            return {
              label: field.label,
              value: `${message} ${ticker}`,
              format: field.format,
              raw: resolved,
              warning: "Allowance is effectively unlimited",
            };
          }
        } catch {
          // Fall through to the plain rendering below.
        }
      }

      const token = descriptor.metadata.token;

      if (token === undefined) {
        return {
          label: field.label,
          value: resolved,
          format: field.format,
          raw: resolved,
          warning:
            "Unknown token: the descriptor carries no decimals, so this is a raw integer",
        };
      }

      return {
        label: field.label,
        value: `${formatUnits(BigInt(resolved), token.decimals)} ${token.ticker}`,
        format: field.format,
        raw: resolved,
      };
    }

    case "amount":
      return {
        label: field.label,
        value: formatNativeAmount(BigInt(resolved)),
        format: field.format,
        raw: resolved,
      };

    case "addressName":
      // Name resolution (ENS, an address book) lives behind the NameResolver
      // seam and is owned elsewhere. Until one answers, the raw checksummed
      // address is shown — never a name Arx made up.
      return {
        label: field.label,
        value: safeChecksum(resolved),
        format: field.format,
      };

    case "date": {
      const seconds = Number(resolved);

      return {
        label: field.label,
        value: Number.isFinite(seconds)
          ? new Date(seconds * 1000).toISOString()
          : resolved,
        format: field.format,
        raw: resolved,
      };
    }

    default:
      return { label: field.label, value: resolved, format: field.format };
  }
}

/**
 * Resolves an ERC-7730 path reference.
 *
 * `#.name` reads the decoded calldata; `@.field` reads the transaction
 * container (the specification defines `@.to`, `@.value`, `@.chainId`,
 * `@.from`). Nested and sliced paths are not implemented; they resolve to
 * `undefined` and surface as an explicit "(unavailable)" field rather than a
 * fabricated value.
 */
export function resolvePath(
  path: string,
  call: DecodedCall,
  transaction: EvmTransaction,
): string | undefined {
  if (path.startsWith("@.")) {
    switch (path.slice(2)) {
      case "to":
        return transaction.to;
      case "value":
        return transaction.value;
      case "chainId":
        return String(transaction.chainId);
      default:
        return undefined;
    }
  }

  const name = path.startsWith("#.") ? path.slice(2) : path;

  return call.args.find((arg) => arg.name === name)?.value;
}

function formatNativeAmount(wei: bigint): string {
  return `${formatUnits(wei, NATIVE_CURRENCY_DECIMALS)} ETH`;
}

function safeChecksum(value: string): string {
  try {
    return getAddress(value);
  } catch {
    return value;
  }
}

function describeChain(chainId: number): string {
  switch (chainId) {
    case 1:
      return "Ethereum (1)";
    case 137:
      return "Polygon (137)";
    case 11155111:
      return "Sepolia (11155111)";
    default:
      return `Chain ${chainId}`;
  }
}
