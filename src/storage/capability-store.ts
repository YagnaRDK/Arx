import type { Capability } from "../types/capability";

export class CapabilityStore {
  private capabilities = new Map<string, Capability>();

  create(capability: Capability): void {
    this.capabilities.set(capability.capabilityId, capability);
  }

  get(capabilityId: string): Capability | undefined {
    return this.capabilities.get(capabilityId);
  }

  revoke(capabilityId: string): boolean {
    const capability = this.capabilities.get(capabilityId);

    if (!capability) {
      return false;
    }

    capability.status = "REVOKED";
    return true;
  }

  consume(capabilityId: string): boolean {
    const capability = this.capabilities.get(capabilityId);

    if (!capability || capability.usage !== "SINGLE_USE") {
      return false;
    }

    capability.status = "CONSUMED";
    return true;
  }
}
