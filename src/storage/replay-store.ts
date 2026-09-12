export class ReplayStore {
  private processedRequests = new Set<string>();

  private getRequestKey(
    capabilityId: string,
    agentId: string,
    nonce: number,
  ): string {
    return `${capabilityId}:${agentId}:${nonce}`;
  }

  hasBeenProcessed(
    capabilityId: string,
    agentId: string,
    nonce: number,
  ): boolean {
    const key = this.getRequestKey(capabilityId, agentId, nonce);

    return this.processedRequests.has(key);
  }

  markProcessed(capabilityId: string, agentId: string, nonce: number): void {
    const key = this.getRequestKey(capabilityId, agentId, nonce);

    this.processedRequests.add(key);
  }
}
