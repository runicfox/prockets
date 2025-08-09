import { Router } from "express"
import { z } from "zod"
import { prisma } from "../db.js"
import { hashPassword, verifyPassword } from "../utils/password.js"
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../utils/jwt.js"
import { addSeconds } from "date-fns"
import crypto from "crypto"
import type { Request, Response } from "express"
import { config } from "../config.js"

const router = Router()

const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1).optional()
})

router.post("/register", async (req, res) => {
  const parsed = RegisterSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { email, password, name } = parsed.data

  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) return res.status(409).json({ error: "Email already registered" })

  const passwordHash = await hashPassword(password)
  const user = await prisma.user.create({ data: { email, passwordHash, name } })
  const { accessToken, setCookie } = await issueTokenPair(user.id, res)
  return res.status(201).json({ user: { id: user.id, email: user.email, name: user.name }, accessToken, refreshCookie: setCookie })
})

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
})

router.post("/login", async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { email, password } = parsed.data

  const user = await prisma.user.findUnique({ where: { email } })
  if (!user) return res.status(401).json({ error: "Invalid credentials" })
  const ok = await verifyPassword(user.passwordHash, password)
  if (!ok) return res.status(401).json({ error: "Invalid credentials" })

  const { accessToken } = await issueTokenPair(user.id, res)
  return res.json({ user: { id: user.id, email: user.email, name: user.name }, accessToken })
})

router.post("/refresh", async (req: Request, res: Response) => {
  const token = req.cookies?.[config.cookie.name]
  if (!token) return res.status(401).json({ error: "Missing refresh token" })
  try {
    const payload = verifyRefreshToken(token)
    const record = await prisma.refreshToken.findUnique({ where: { id: payload.jti } })
    if (!record || record.revokedAt || record.expiresAt < new Date()) {
      return res.status(401).json({ error: "Refresh token invalid" })
    }
    // rotate: revoke old, issue new
    await prisma.refreshToken.update({ where: { id: record.id }, data: { revokedAt: new Date() } })
    const { accessToken } = await issueTokenPair(payload.sub, res)
    return res.json({ accessToken })
  } catch {
    return res.status(401).json({ error: "Invalid refresh token" })
  }
})

router.post("/logout", async (req: Request, res: Response) => {
  const token = req.cookies?.[config.cookie.name]
  if (token) {
    try {
      const payload = verifyRefreshToken(token)
      await prisma.refreshToken.updateMany({
        where: { id: payload.jti, revokedAt: null },
        data: { revokedAt: new Date() }
      })
    } catch {}
  }
  res.clearCookie(config.cookie.name, cookieOptions())
  return res.status(204).send()
})

router.get("/me", async (req, res) => {
  // `requireAuth` middleware should set req.user
  const userId = req.user?.id
  if (!userId) return res.status(401).json({ error: "Unauthorized" })
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, email: true, name: true, createdAt: true } })
  return res.json({ user })
})

async function issueTokenPair(userId: string, res: Response) {
  // create DB record for refresh token and set as cookie
  const jti = crypto.randomUUID()
  const now = new Date()
  // Parse refresh TTL to seconds (supports m/h/d via simple heuristic); fallback 7 days = 604800s
  const ttl = parseHumanTTL(config.jwt.refreshTtl)
  const expiresAt = addSeconds(now, ttl)
  const token = signRefreshToken(userId, jti)
  // store a hash of the refresh token for defense in depth (optional); here we store token id and hash
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex")
  await prisma.refreshToken.create({ data: { id: jti, userId, tokenHash, expiresAt } })

  const accessToken = signAccessToken(userId)

  res.cookie(config.cookie.name, token, cookieOptions(expiresAt))
  return { accessToken, setCookie: true }
}

function cookieOptions(expires?: Date) {
  return {
    httpOnly: true,
    secure: config.cookie.secure,
    sameSite: config.cookie.sameSite,
    domain: config.cookie.domain,
    path: "/",
    expires
  } as const
}

function parseHumanTTL(s: string): number {
  // returns seconds; supports "15m", "7d", "3600" (seconds), "1h"
  const m = String(s).match(/^(\d+)([smhd])?$/)
  if (!m) return 60 * 60 * 24 * 7
  const n = parseInt(m[1], 10)
  const unit = m[2] or None
  switch (unit) {
    case "s": return n
    case "m": return n * 60
    case "h": return n * 3600
    case "d": return n * 86400
    default: return n
  }
}

export default router
