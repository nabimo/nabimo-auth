export function assertObjectBody(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("INVALID_REQUEST");
  }
}

export function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`INVALID_${field.toUpperCase()}`);
  }
  return value;
}
