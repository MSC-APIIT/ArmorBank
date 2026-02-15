import { z } from "zod";

const EnvSchema = z.object({
  MONGODB_URI: z.string().min(1),
  MONGODB_DB: z.string().min(1).default("bank_auth"),

  JWT_ACCESS_SECRET: z.string().min(16),
  JWT_REFRESH_SECRET: z.string().min(16),

  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900), // 15m
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().default(60 * 60 * 24 * 7), // 7d

  GMAIL_USER: z.string().min(1),
  GMAIL_APP_PASSWORD: z.string().min(1),

  DUMMY_BCRYPT_HASH: z.string().min(60),

  COOKIE_SECURE: z
    .string()
    .optional()
    .transform((v) => v !== "false")
    .default("true"),

  TOTP_ISSUER: z.string().min(1).default("Bank-Auth AuthArmor"),
  MFA_ENC_KEY: z.string().min(32),

  LOCATION_RESTRICTED_ROLES: z.string().optional().default("admin,staff"),
  MFA_ROLES: z.string().optional().default("customer"),

  HIGH_RISK_THRESHOLD: z.coerce.number().default(70),
  MFA_REQUIRED_THRESHOLD: z.coerce.number().default(30),

  MFA_FAIL_WINDOW_SECONDS: z.coerce.number().default(600),
  MFA_FAIL_LIMIT: z.coerce.number().default(3),

  ACCOUNT_LOCK_SECONDS: z.coerce.number().default(60 * 60 * 24),
});

export const env = EnvSchema.parse(process.env);
