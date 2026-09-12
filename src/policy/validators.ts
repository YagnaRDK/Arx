import { CapabilitySchema } from "../types/capability";
import { IntentSchema } from "../types/intent";

export function validateCapability(input: unknown) {
  return CapabilitySchema.safeParse(input);
}

export function validateIntent(input: unknown) {
  return IntentSchema.safeParse(input);
}
