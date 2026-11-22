
import type { NextFunction, Request, Response } from "express";
import { validateSession } from "./session.js";

export interface AuthenticatedUser {
  id: string;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      sessionId?: string;
      organizationId?: string;
      organizationRole?: "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";
    }
  }
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const token = req.cookies?.session;

  if (typeof token !== "string") {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  try {
    const session = await validateSession(token);

    if (!session) {
      res.status(401).json({ error: "Invalid or expired session." });
      return;
    }

    req.user = {
      id: session.userId,
      email: session.email,
    };

    req.sessionId = session.id;

    next();
  } catch (error) {
    console.error("Session validation failed:", error);
    res.status(500).json({ error: "Unable to validate session." });
  }
}
