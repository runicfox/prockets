import type { Request, Response, NextFunction } from "express"
import { verifyAccessToken } from "../utils/jwt.js"

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const hdr = req.headers.authorization
  const token = hdr?.startsWith("Bearer ") ? hdr.slice(7) : null
  if (!token) return res.status(401).json({ error: "Missing Authorization header" })
  try {
    const payload = verifyAccessToken(token)
    req.user = { id: payload.sub }
    next()
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" })
  }
}
