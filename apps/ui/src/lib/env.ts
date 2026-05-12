import { z } from "zod";

const envSchema = z.object({
  OPERATOR_PASSWORD: z.string().min(8, "OPERATOR_PASSWORD must be at least 8 characters"),
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),
  DATABASE_URL: z.string().url().optional(),
  API_BASE_URL: z.string().url().default("http://localhost:8000"),
});

type Env = z.infer<typeof envSchema>;

function parseEnv(): Env {
  const result = envSchema.safeParse({
    OPERATOR_PASSWORD: process.env["OPERATOR_PASSWORD"],
    SESSION_SECRET: process.env["SESSION_SECRET"],
    DATABASE_URL: process.env["DATABASE_URL"],
    API_BASE_URL: process.env["API_BASE_URL"],
  });

  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Missing or invalid environment variables:\n${formatted}`);
  }

  return result.data;
}

export const env = parseEnv();
