import dotenv from "dotenv"
dotenv.config()

const get = (key: string, fallback?: string) => {
  const v = process.env[key]
  if (v === undefined || v === "") {
    if (fallback !== undefined) return fallback
    throw new Error(`Missing env ${key}`)
  }
  return v
}

export const config = {
  port: Number(get("PORT", "8080")),
  nodeEnv: get("NODE_ENV", "development"),
  corsOrigins: get("CORS_ORIGINS", "http://localhost:5173").split(","),
  jwt: {
    accessSecret: get("JWT_ACCESS_SECRET"),
    refreshSecret: get("JWT_REFRESH_SECRET"),
    accessTtl: get("JWT_ACCESS_TTL", "15m"),
    refreshTtl: get("JWT_REFRESH_TTL", "7d")
  },
  cookie: {
    name: get("COOKIE_NAME", "refresh_token"),
    domain: get("COOKIE_DOMAIN", "localhost"),
    secure: get("COOKIE_SECURE", "false") === "true",
    sameSite: (get("COOKIE_SAMESITE", "Lax") as "Lax"|"Strict"|"None")
  }
}
