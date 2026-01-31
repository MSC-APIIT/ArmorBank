import { Redis } from "@upstash/redis";

const redis = Redis.fromEnv();

type Input = {
  key: string;
  limit: number;
  windowSeconds: number;
  blockSeconds?: number;
};

export async function rateLimit({
  key,
  limit,
  windowSeconds,
  blockSeconds = 300,
}: Input): Promise<{ ok: true } | { ok: false; retryAfterSeconds: number }> {
  const lockKey = `${key}:lock`;

  // 1. Already blocked?
  const lockTtl = await redis.ttl(lockKey);

  if (lockTtl > 0) {
    return { ok: false, retryAfterSeconds: lockTtl };
  }

  // 2. Count attempts (atomic)
  const count = await redis.incr(key);

  // 3. First attempt → start window
  if (count === 1) {
    await redis.expire(key, windowSeconds);
  }

  // 4. Over limit → block
  if (count > limit) {
    await redis.set(lockKey, "1", { ex: blockSeconds });
    await redis.del(key);
    return { ok: false, retryAfterSeconds: blockSeconds };
  }

  return { ok: true };
}
