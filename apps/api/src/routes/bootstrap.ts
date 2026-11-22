
import { Router } from "express";
import { randomBytes, createHash } from "node:crypto";
import { z } from "zod";
import { prisma } from "../db.js";
import { hashPassword } from "../auth/password.js";
import { createSession } from "../auth/session.js";

const router = Router();

const bootstrapSchema = z.object({
  setupKey: z.string().min(32),
  email: z.string().trim().email().max(254),
  password: z.string().min(12).max(128),
  organizationName: z.string().trim().min(2).max(100),
});

router.post("/initial-owner", async (req, res) => {
  const validation = bootstrapSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      error: "Invalid bootstrap request.",
    });
  }

  const expectedKey = process.env.INITIAL_OWNER_SETUP_KEY;

  if (!expectedKey || expectedKey.length < 32) {
    return res.status(503).json({
      error: "Initial owner setup is not configured.",
    });
  }

  const suppliedHash = createHash("sha256")
    .update(validation.data.setupKey)
    .digest();

  const expectedHash = createHash("sha256")
    .update(expectedKey)
    .digest();

  if (!suppliedHash.equals(expectedHash)) {
    return res.status(403).json({
      error: "Invalid setup key.",
    });
  }

  try {
    const email = validation.data.email.toLowerCase();
    const passwordHash = await hashPassword(validation.data.password);
    const slug = `${validation.data.organizationName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")}-${randomBytes(4).toString("hex")}`;

    const result = await prisma.$transaction(async (tx) => {
  await tx.$queryRaw`
    SELECT pg_advisory_xact_lock(7420192601)
  `;

  const existingUsers = await tx.user.count();

  if (existingUsers > 0) {
    throw new Error("INITIAL_OWNER_ALREADY_EXISTS");
  }

      const user = await tx.user.create({
        data: {
          email,
          passwordHash,
        },
      });

      const organization = await tx.organization.create({
        data: {
          name: validation.data.organizationName,
          slug,
        },
      });

      await tx.organizationMembership.create({
        data: {
          userId: user.id,
          organizationId: organization.id,
          role: "OWNER",
        },
      });

      return { user, organization };
    });

    const { token, expiresAt } = await createSession(
      result.user.id,
      req.get("user-agent") ?? undefined
    );

    res.cookie("session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      expires: expiresAt,
    });

    return res.status(201).json({
      message: "Initial owner created successfully.",
      user: {
        id: result.user.id,
        email: result.user.email,
      },
      organization: {
        id: result.organization.id,
        name: result.organization.name,
        slug: result.organization.slug,
      },
    });
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "INITIAL_OWNER_ALREADY_EXISTS"
    ) {
      return res.status(409).json({
        error: "Initial owner setup has already been completed.",
      });
    }

    console.error("Initial owner setup failed:", error);

    return res.status(500).json({
      error: "Unable to create initial owner.",
    });
  }
});

export default router;
