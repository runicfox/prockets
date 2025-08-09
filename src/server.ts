import express from "express"
import helmet from "helmet"
import morgan from "morgan"
import cors from "cors"
import cookieParser from "cookie-parser"
import rateLimit from "express-rate-limit"
import { config } from "./config.js"
import { requireAuth } from "./middleware/auth.js"
import authRoutes from "./routes/auth.js"

const app = express()

app.use(helmet())
app.use(express.json())
app.use(cookieParser())
app.use(morgan("dev"))
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true) // allow curl/local
    if (config.corsOrigins.includes(origin)) return cb(null, true)
    return cb(new Error("CORS blocked"), false)
  },
  credentials: true
}))

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 })
app.use(limiter)

app.get("/health", (_req, res) => res.json({ ok: true }))

app.use("/auth", authRoutes)
app.get("/protected/ping", requireAuth, (_req, res) => res.json({ pong: true }))

app.use((err: any, _req: any, res: any, _next: any) => {
  console.error(err)
  res.status(500).json({ error: "Internal Server Error" })
})

app.listen(config.port, () => {
  console.log(`Auth API listening on http://localhost:${config.port}`)
})
