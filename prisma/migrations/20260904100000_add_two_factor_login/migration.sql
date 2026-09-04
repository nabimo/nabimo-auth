-- Add the persisted challenge type used to complete password logins protected by TOTP.
ALTER TYPE "VerificationType" ADD VALUE IF NOT EXISTS 'TWO_FACTOR_LOGIN';
