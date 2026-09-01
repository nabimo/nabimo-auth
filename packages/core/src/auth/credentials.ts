export function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!normalized || normalized.length > 320 || !normalized.includes("@")) {
    throw new Error("Invalid email address");
  }
  return normalized;
}

export function normalizePhone(phone: string): string {
  const normalized = phone.trim().replace(/[\s().-]/g, "");
  if (!/^\+?[1-9]\d{6,14}$/.test(normalized)) {
    throw new Error("Invalid phone number");
  }
  return normalized;
}
