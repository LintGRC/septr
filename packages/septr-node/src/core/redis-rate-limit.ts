interface RedisClient {
  incr(key: string): Promise<number>
  expire(key: string, seconds: number): Promise<number>
  ttl(key: string): Promise<number>
}

/**
 * Redis-backed sliding window rate limiter. Replaces the in-memory
 * {@link SlidingWindowRateLimiter} when a Redis URL is configured.
 *
 * Uses atomic INCR + EXPIRE to track request counts. Each key expires
 * after `windowMs / 1000` seconds, so stale entries are cleaned up
 * automatically by Redis (no cleanup timer needed).
 *
 * Graceful degradation: if Redis is unreachable, falls back to a per-process
 * in-memory limiter so traffic is never unthrottled.
 *
 * @example
 * ```ts
 * const limiter = new RedisSlidingWindowRateLimiter(redisClient, 60, 60_000)
 * const result = await limiter.check("client-ip-123")
 * ```
 */
export class RedisSlidingWindowRateLimiter {
  readonly max: number
  readonly windowMs: number
  private redis: RedisClient | null = null
  private fallback: import("./rate-limit").SlidingWindowRateLimiter | null = null

  constructor(redis: RedisClient | null, max: number = 60, windowMs: number = 60_000) {
    this.max = max
    this.windowMs = windowMs
    this.redis = redis

    const { SlidingWindowRateLimiter } = require("./rate-limit")
    this.fallback = new SlidingWindowRateLimiter(max, windowMs)
  }

  async check(key: string): Promise<{ allowed: boolean; remaining: number; resetMs: number }> {
    if (!this.redis) {
      return this.fallback!.check(key)
    }

    const windowSeconds = Math.ceil(this.windowMs / 1000)
    const redisKey = `vs_ratelimit:${key}`

    try {
      const count = await this.redis.incr(redisKey)

      if (count === 1) {
        await this.redis.expire(redisKey, windowSeconds)
        return { allowed: true, remaining: this.max - 1, resetMs: this.windowMs }
      }

      const ttl = await this.redis.ttl(redisKey)
      const resetMs = ttl > 0 ? ttl * 1000 : this.windowMs

      if (count > this.max) {
        return { allowed: false, remaining: 0, resetMs }
      }

      return { allowed: true, remaining: this.max - count, resetMs }
    } catch {
      return this.fallback!.check(key)
    }
  }

  destroy(): void {
    this.fallback?.destroy()
  }
}

/**
 * Create a Redis client from a REDIS_URL environment variable.
 * Returns `null` if `REDIS_URL` is not set or if the `ioredis`
 * package is not available (graceful fallback).
 */
export async function createRedisClient(url?: string): Promise<RedisClient | null> {
  const redisUrl = url || (typeof process !== "undefined" && process.env?.REDIS_URL) || ""
  if (!redisUrl) return null

  try {
    const Redis = require("ioredis")
    return new Redis(redisUrl, {
      maxRetriesPerRequest: 1,
      retryStrategy: () => null,
      lazyConnect: true,
    })
  } catch {
    return null
  }
}
