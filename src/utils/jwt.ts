import jwt from "jsonwebtoken"
import { config } from "../config.js"

export type AccessPayload = { sub: string; type: "access" }
export type RefreshPayload = { sub: string; jti: string; type: "refresh" }

export function signAccessToken(userId: string) {
  const payload: AccessPayload = { sub: userId, type: "access" }
  return jwt.sign(payload, config.jwt.accessSecret, { expiresIn: config.jwt.accessTtl })
}

export function signRefreshToken(userId: string, jti: string) {
  const payload: RefreshPayload = { sub: userId, jti, type: "refresh" }
  return jwt.sign(payload, config.jwt.refreshSecret, { expiresIn: config.jwt.refreshTtl })
}

export function verifyAccessToken(token: string): AccessPayload {
  const payload = jwt.verify(token, config.jwt.accessSecret) as AccessPayload
  if (payload.type !== "access") throw new Error("Invalid token type")
  return payload
}

export function verifyRefreshToken(token: string): RefreshPayload {
  const payload = jwt.verify(token, config.jwt.refreshSecret) as RefreshPayload
  if (payload.type !== "refresh") throw new Error("Invalid token type")
  return payload
}
