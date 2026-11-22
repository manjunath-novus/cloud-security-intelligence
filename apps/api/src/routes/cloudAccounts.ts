
import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth } from "../auth/middleware.js";
import {
  requireOrganization,
  requireOrganizationAdmin,
} from "../auth/organization.js";

const router = Router();

router.use(requireAuth, requireOrganization);

const createCloudAccountSchema = z.object({
  name: z.string().trim().min(2).max(100),
  provider: z.enum(["AZURE", "AWS", "GCP"]),
  accountId: z.string().trim().min(1).max(150),
  environment: z
    .enum(["development", "staging", "production"])
    .default("development"),
  region: z.string().trim().min(1).max(100).optional(),
});

router.get("/", async (req, res) => {
  try {
    const accounts = await prisma.cloudAccount.findMany({
      where: {
        organizationId: req.organizationId!,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    return res.status(200).json({
      count: accounts.length,
      accounts,
    });
  } catch (error) {
    console.error("Failed to fetch cloud accounts:", error);
    return res.status(500).json({
      error: "Unable to fetch cloud accounts.",
    });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const account = await prisma.cloudAccount.findFirst({
      where: {
        id: req.params.id,
        organizationId: req.organizationId!,
      },
    });

    if (!account) {
      return res.status(404).json({
        error: "Cloud account not found.",
      });
    }

    return res.status(200).json({ account });
  } catch (error) {
    console.error("Failed to fetch cloud account:", error);
    return res.status(500).json({
      error: "Unable to fetch cloud account.",
    });
  }
});

router.patch(
  "/:id/deactivate",
  requireOrganizationAdmin,
  async (req, res) => {
    try {
      const existingAccount = await prisma.cloudAccount.findFirst({
        where: {
          id: String(req.params.id),
          organizationId: req.organizationId!,
        },
      });

      if (!existingAccount) {
        return res.status(404).json({
          error: "Cloud account not found.",
        });
      }

      if (!existingAccount.isActive) {
        return res.status(409).json({
          error: "Cloud account is already inactive.",
        });
      }

      const account = await prisma.cloudAccount.updateMany({
        where: {
          id: String(req.params.id),
          organizationId: req.organizationId!,
        },
        data: {
          isActive: false,
        },
      });

      return res.status(200).json({
        message: "Cloud account deactivated successfully.",
        account: {
          ...existingAccount,
          isActive: false,
        },
      });
    } catch (error) {
      console.error("Cloud account deactivation failed:", error);
      return res.status(500).json({
        error: "Unable to deactivate cloud account.",
      });
    }
  }
);

router.patch(
  "/:id/activate",
  requireOrganizationAdmin,
  async (req, res) => {
    try {
      const existingAccount = await prisma.cloudAccount.findFirst({
        where: {
          id: String(req.params.id),
          organizationId: req.organizationId!,
        },
      });

      if (!existingAccount) {
        return res.status(404).json({
          error: "Cloud account not found.",
        });
      }

      if (existingAccount.isActive) {
        return res.status(409).json({
          error: "Cloud account is already active.",
        });
      }

      await prisma.cloudAccount.updateMany({
        where: {
          id: String(req.params.id),
          organizationId: req.organizationId!,
        },
        data: {
          isActive: true,
        },
      });

      return res.status(200).json({
        message: "Cloud account activated successfully.",
        account: {
          ...existingAccount,
          isActive: true,
        },
      });
    } catch (error) {
      console.error("Cloud account activation failed:", error);
      return res.status(500).json({
        error: "Unable to activate cloud account.",
      });
    }
  }
);

router.post("/", requireOrganizationAdmin, async (req, res) => {
  const validation = createCloudAccountSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      error: "Validation failed",
      details: validation.error.issues,
    });
  }

  const data = validation.data;

  try {
    const existingAccount = await prisma.cloudAccount.findFirst({
      where: {
        organizationId: req.organizationId!,
        provider: data.provider,
        accountId: data.accountId,
      },
    });

    if (existingAccount) {
      return res.status(409).json({
        error: "This cloud account is already registered.",
      });
    }

    const cloudAccount = await prisma.cloudAccount.create({
      data: {
        organizationId: req.organizationId!,
        name: data.name,
        provider: data.provider,
        accountId: data.accountId,
        environment: data.environment,
        region: data.region,
      },
    });

    return res.status(201).json({
      message: "Cloud account registered successfully.",
      account: cloudAccount,
    });
  } catch (error) {
    console.error("Cloud account registration failed:", error);
    return res.status(500).json({
      error: "Unable to register cloud account.",
    });
  }
});

export default router;
