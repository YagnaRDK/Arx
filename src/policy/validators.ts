import { CapabilitySchema, type Capability } from "../types/capability";

import { IntentSchema, type Intent } from "../types/intent";

export function validateCapability(
  input: unknown,
): { success: true; data: Capability } | { success: false; errors: string[] } {
  const result = CapabilitySchema.safeParse(input);

  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  }

  return {
    success: false,
    errors: result.error.issues.map(
      (issue) => `${issue.path.join(".")}: ${issue.message}`,
    ),
  };
}

export function validateIntent(
  input: unknown,
): { success: true; data: Intent } | { success: false; errors: string[] } {
  const result = IntentSchema.safeParse(input);

  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  }

  return {
    success: false,
    errors: result.error.issues.map(
      (issue) => `${issue.path.join(".")}: ${issue.message}`,
    ),
  };
}
