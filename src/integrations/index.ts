/**
 * Barrel for the sponsor integration adapters.
 *
 * Everything here implements a seam from `src/core/seams.ts` (or, for x402 and
 * Arc, a transport/rail the seams sit on top of). Nothing here reaches into the
 * policy layer: an adapter's only job is to answer a question, or to say
 * clearly that it could not.
 */

export {
  IntegrationRegistry,
  integrationRegistry,
  type DescribeOptions,
  type IntegrationDescriptor,
  type IntegrationState,
} from "./registry";

export * from "./ens";
export * from "./graph";
export * from "./x402";
export * from "./world";
export * from "./privy";
export * from "./circle";
export * from "./uniswap";
export * from "./oneinch";
export * from "./chainlink";

export { requestJson, failureToUnavailable, type HttpOutcome } from "./http";
export { cacheKey, claimOnce, invalidateCache, readCache, writeCache } from "./cache";
