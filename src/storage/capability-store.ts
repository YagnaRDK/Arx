import type { Capability } from "../types/capability";

export class CapabilityStore {
  private capabilities = new Map<string, Capability>();

  create(capability: Capability): Capability {
    if (this.capabilities.has(capability.capabilityId)) {
      throw new Error("Capability ID already exists");
    }

    this.capabilities.set(capability.capabilityId, structuredClone(capability));

    return capability;
  }

  get(capabilityId: string): Capability | undefined {
    const capability = this.capabilities.get(capabilityId);

    if (!capability) {
      return undefined;
    }

    return structuredClone(capability);
  }

  revoke(capabilityId: string): Capability | undefined {
    const capability = this.capabilities.get(capabilityId);

    if (!capability) {
      return undefined;
    }

    capability.status = "REVOKED";

    return structuredClone(capability);
  }

  consume(capabilityId: string): Capability | undefined {
    const capability = this.capabilities.get(capabilityId);

    if (!capability || capability.usage !== "SINGLE_USE") {
      return undefined;
    }

    capability.status = "CONSUMED";

    return structuredClone(capability);
  }
}
