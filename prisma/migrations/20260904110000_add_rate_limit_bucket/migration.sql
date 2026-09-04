-- Persist fixed-window rate-limit counters.
CREATE TABLE "RateLimitBucket" (
  "id" TEXT NOT NULL,
  "key" TEXT NOT NULL,
  "windowStartedAt" TIMESTAMP(3) NOT NULL,
  "count" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "RateLimitBucket_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RateLimitBucket_key_windowStartedAt_key"
  ON "RateLimitBucket"("key", "windowStartedAt");

CREATE INDEX "RateLimitBucket_updatedAt_idx"
  ON "RateLimitBucket"("updatedAt");
