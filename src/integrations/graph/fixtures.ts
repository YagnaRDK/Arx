/**
 * Offline fixtures for the Graph risk provider.
 *
 * These exist so the adversarial demo scenarios are reproducible without an
 * API key, and every result built from them carries `source:
 * "graph-token-api:FIXTURES"` — in the profile, in the signal evidence, and in
 * `/integrations`. A fixture must never be able to read as live data: the whole
 * value of the risk score is that an operator can trust where it came from.
 */

export type AddressFixture = {
  /** Unix seconds of the first transfer the fixture claims to have seen. */
  firstSeenAt: number;
  transferCount: number;
  uniqueCounterparties: number;
  isContract: boolean;
  labels: string[];
  note: string;
};

/**
 * Keys are lowercase addresses. The three shapes the demo needs: an
 * established counterparty, a fresh address with almost no history (the
 * classic drainer profile), and a well-known contract.
 */
export const ADDRESS_FIXTURES: Readonly<Record<string, AddressFixture>> = {
  // Vitalik's address: long history, high counterparty diversity.
  "0xd8da6bf26964af9d7eed9e03e53415d37aa96045": {
    firstSeenAt: 1_438_000_000,
    transferCount: 5_000,
    uniqueCounterparties: 2_400,
    isContract: false,
    labels: ["long-lived-eoa"],
    note: "Fixture: established EOA with deep history.",
  },
  // Deliberate drainer profile for the demo: minutes old, one counterparty.
  "0x000000000000000000000000000000000000dead": {
    firstSeenAt: 1_789_000_000,
    transferCount: 1,
    uniqueCounterparties: 1,
    isContract: false,
    labels: ["fixture-fresh-recipient"],
    note: "Fixture: freshly funded address, single counterparty.",
  },
  // Canonical WETH9 on mainnet — a contract with a very long history.
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": {
    firstSeenAt: 1_513_000_000,
    transferCount: 100_000,
    uniqueCounterparties: 50_000,
    isContract: true,
    labels: ["weth9", "long-lived-contract"],
    note: "Fixture: canonical WETH9, extremely long history.",
  },
};

export function fixtureFor(address: string): AddressFixture | undefined {
  return ADDRESS_FIXTURES[address.toLowerCase()];
}
