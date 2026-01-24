import { z } from "zod";

const EnvSchema = z.object({
  MONGODB_URI: z.string().min(1),
  MONGODB_DB: z.string().min(1).default("bank_auth"),

  JWT_ACCESS_SECRET: z.string().min(16),
  JWT_REFRESH_SECRET: z.string().min(16),

  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900), // 15m
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().default(60 * 60 * 24 * 7), // 7d

  COOKIE_SECURE: z
    .string()
    .optional()
    .transform((v) => v !== "false")
    .default("true"),
});

export const env = EnvSchema.parse(process.env);
