import { getDb } from "@/server/db/mongo";

type RateLimitInput = {
  key: string;
  limit: number;
  windowSeconds: number;
  blockSeconds?: number;
};

export async function rateLimit({
  key,
  limit,
  windowSeconds,
  blockSeconds = 60 * 5,
}: RateLimitInput): Promise<
  { ok: true } | { ok: false; retryAfterSeconds: number }
> {
  const db = await getDb();
  const col = db.collection("rate_limits");

  const now = new Date();
  const windowStart = new Date(now.getTime() - windowSeconds * 1000);
  const expiresAt = new Date(now.getTime() + windowSeconds * 1000);

  const existing = await col.findOne<{
    blockedUntil?: Date;
    count?: number;
    windowStart?: Date;
  }>({ key });

  if (existing?.blockedUntil && existing.blockedUntil > now) {
    return {
      ok: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((existing.blockedUntil.getTime() - now.getTime()) / 1000),
      ),
    };
  }

  // Reset window if old
  const shouldReset =
    !existing?.windowStart || existing.windowStart < windowStart;

  if (shouldReset) {
    await col.updateOne(
      { key },
      {
        $set: { key, count: 1, windowStart: now, expiresAt },
        $unset: { blockedUntil: "" },
      },
      { upsert: true },
    );
    return { ok: true };
  }

  // Increment
  const updated = await col.findOneAndUpdate(
    { key },
    { $inc: { count: 1 }, $set: { expiresAt } },
    { returnDocument: "after", upsert: true },
  );

  const count = updated?.value?.count ?? 0;
  if (count > limit) {
    const blockedUntil = new Date(now.getTime() + blockSeconds * 1000);
    await col.updateOne({ key }, { $set: { blockedUntil } });

    return { ok: false, retryAfterSeconds: blockSeconds };
  }

  return { ok: true };
}
