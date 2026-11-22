
import type { NextFunction, Request, Response } from "express";
import { prisma } from "../db.js";

export async function requireOrganization(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  const organizationId = req.get("x-organization-id");

  if (!organizationId) {
    res.status(400).json({
      error: "X-Organization-Id header is required.",
    });
    return;
  }

  try {
    const membership = await prisma.organizationMembership.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId,
        },
      },
      include: {
        organization: {
          select: {
            id: true,
            status: true,
          },
        },
      },
    });

    if (
      !membership ||
      membership.organization.status !== "ACTIVE"
    ) {
      res.status(403).json({
        error: "You do not have access to this organization.",
      });
      return;
    }

    req.organizationId = membership.organizationId;
    req.organizationRole = membership.role;

    next();
  } catch (error) {
    console.error("Organization authorization failed:", error);
    res.status(500).json({
      error: "Unable to verify organization access.",
    });
  }
}

export function requireOrganizationAdmin(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (
    req.organizationRole !== "OWNER" &&
    req.organizationRole !== "ADMIN"
  ) {
    res.status(403).json({
      error: "Organization administrator permissions required.",
    });
    return;
  }

  next();
}
