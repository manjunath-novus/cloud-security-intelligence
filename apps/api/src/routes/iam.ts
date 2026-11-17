import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { discoverCloudIam } from "../discovery/iam-discovery.service.js";
import { scanCloudAccountIam } from "../security/iam-security.service.js";
import { getPermissionIntelligence } from "../security/permission-intelligence.service.js";
import { calculateIamRiskTrend } from "../security/iam-risk-history.js";

const router = Router();

const accountIdSchema = z.string().uuid();

const accountQuerySchema = z.object({
  cloudAccountId: accountIdSchema,
});

const createApprovalSchema = z.object({
  cloudAccountId: accountIdSchema,
  cloudIdentityId: accountIdSchema,
  ruleId: z.string().min(1).max(100),
  recommendationTitle: z.string().min(1).max(200),
  requestedBy: z.string().min(1).max(100),
  requestReason: z.string().min(10).max(1000),
});

const approvalDecisionSchema = z.object({
  action: z.enum(["APPROVE", "REJECT"]),
  reviewedBy: z.string().min(1).max(100),
  reviewComment: z.string().max(1000).optional(),
});

const createVerificationSchema = z.object({
  verifiedBy: z.string().min(1).max(100),
  evidence: z.string().max(2000).optional(),
  notes: z.string().max(1000).optional(),
});

const updateVerificationSchema = z.object({
  status: z.enum(["SUCCESSFUL", "FAILED"]),
  evidence: z.string().max(2000).optional(),
  notes: z.string().max(1000).optional(),
});
// GET /api/iam/history/:cloudAccountId
router.get("/history/:cloudAccountId", async (req, res) => {
  const validation = accountIdSchema.safeParse(req.params.cloudAccountId);

  if (!validation.success) {
    return res.status(400).json({
      error: "Invalid cloud account ID.",
    });
  }

  try {
    const cloudAccountId = validation.data;

    const account = await prisma.cloudAccount.findUnique({
      where: { id: cloudAccountId },
      select: {
        id: true,
        name: true,
      },
    });

    if (!account) {
      return res.status(404).json({
        error: "Cloud account not found.",
      });
    }

    const scans = await prisma.iamRiskScan.findMany({
      where: { cloudAccountId },
      orderBy: { createdAt: "desc" },
      take: 20,
    });

    const latest = scans[0];
    const previous = scans[1];
    const scoreChange =
      latest && previous ? latest.riskScore - previous.riskScore : null;

    const trend = calculateIamRiskTrend(
      latest?.riskScore ?? null,
      previous?.riskScore ?? null,
    );

    return res.status(200).json({
      account,
      total: scans.length,
      scans,
      trend,
    });
  } catch (error) {
    console.error("Failed to retrieve IAM scan history:", error);

    return res.status(500).json({
      error: "Unable to retrieve IAM scan history.",
    });
  }
});

// POST /api/iam/discover/:cloudAccountId
router.post("/discover/:cloudAccountId", async (req, res) => {
  const validation = accountIdSchema.safeParse(req.params.cloudAccountId);

  if (!validation.success) {
    return res.status(400).json({
      error: "Invalid cloud account ID.",
    });
  }

  try {
    const discovery = await discoverCloudIam(validation.data);

    return res.status(200).json({
      message: "IAM discovery completed successfully.",
      discovery,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "IAM discovery failed.";

    if (message === "Cloud account not found.") {
      return res.status(404).json({ error: message });
    }

    if (
      message === "Cloud account is inactive." ||
      message.startsWith("IAM discovery is not yet implemented")
    ) {
      return res.status(409).json({ error: message });
    }

    console.error("IAM discovery failed:", error);

    return res.status(500).json({
      error: "Unable to complete IAM discovery.",
    });
  }
});
router.post("/scan/:cloudAccountId", async (req, res) => {
  try {
    const { cloudAccountId } = req.params;

    const result = await scanCloudAccountIam(cloudAccountId);

    res.status(200).json({
      message: "IAM security scan completed successfully.",
      scan: result,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to scan IAM security.";

    const status =
      message === "Cloud account not found"
        ? 404
        : message === "Cloud account is inactive"
          ? 409
          : 500;

    res.status(status).json({ error: message });
  }
});

// GET /api/iam/identities?cloudAccountId=...
router.get("/identities", async (req, res) => {
  const validation = accountQuerySchema.safeParse(req.query);

  if (!validation.success) {
    return res.status(400).json({
      error: "A valid cloudAccountId is required.",
    });
  }

  try {
    const identities = await prisma.cloudIdentity.findMany({
      where: {
        cloudAccountId: validation.data.cloudAccountId,
      },
      include: {
        roleAssignments: {
          include: {
            cloudRoleDefinition: true,
          },
        },
      },
      orderBy: {
        displayName: "asc",
      },
    });

    return res.status(200).json({
      identities,
      total: identities.length,
    });
  } catch (error) {
    console.error("Failed to retrieve IAM identities:", error);

    return res.status(500).json({
      error: "Unable to retrieve IAM identities.",
    });
  }
});

// GET /api/iam/permission-analysis?cloudAccountId=...
router.get("/permission-analysis", async (req, res) => {
  const validation = accountQuerySchema.safeParse(req.query);

  if (!validation.success) {
    return res.status(400).json({
      error: "A valid cloudAccountId is required.",
    });
  }

  try {
    const analysis = await getPermissionIntelligence(
      validation.data.cloudAccountId,
    );

    return res.status(200).json({
      message: "Permission intelligence analysis completed successfully.",
      analysis,
    });
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Unable to analyze IAM permissions.";

    if (message === "Cloud account not found") {
      return res.status(404).json({ error: message });
    }

    if (message === "Cloud account is inactive") {
      return res.status(409).json({ error: message });
    }

    console.error("Permission intelligence analysis failed:", error);

    return res.status(500).json({
      error: "Unable to analyze IAM permissions.",
    });
  }
});

// GET /api/iam/roles?cloudAccountId=...
router.get("/roles", async (req, res) => {
  const validation = accountQuerySchema.safeParse(req.query);

  if (!validation.success) {
    return res.status(400).json({
      error: "A valid cloudAccountId is required.",
    });
  }

  try {
    const roles = await prisma.cloudRoleDefinition.findMany({
      where: {
        cloudAccountId: validation.data.cloudAccountId,
      },
      include: {
        _count: {
          select: {
            roleAssignments: true,
          },
        },
      },
      orderBy: {
        name: "asc",
      },
    });

    return res.status(200).json({
      roles,
      total: roles.length,
    });
  } catch (error) {
    console.error("Failed to retrieve IAM roles:", error);

    return res.status(500).json({
      error: "Unable to retrieve IAM roles.",
    });
  }
});

// GET /api/iam/assignments?cloudAccountId=...
router.get("/assignments", async (req, res) => {
  const validation = accountQuerySchema.safeParse(req.query);

  if (!validation.success) {
    return res.status(400).json({
      error: "A valid cloudAccountId is required.",
    });
  }

  try {
    const assignments = await prisma.cloudRoleAssignment.findMany({
      where: {
        cloudAccountId: validation.data.cloudAccountId,
      },
      include: {
        cloudIdentity: true,
        cloudRoleDefinition: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    return res.status(200).json({
      assignments,
      total: assignments.length,
    });
  } catch (error) {
    console.error("Failed to retrieve IAM assignments:", error);

    return res.status(500).json({
      error: "Unable to retrieve IAM assignments.",
    });
  }
});

// POST /api/iam/approvals
router.post("/approvals", async (req, res) => {
  const validation = createApprovalSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      error: "Invalid approval request.",
      details: validation.error.flatten(),
    });
  }

  try {
    const {
      cloudAccountId,
      cloudIdentityId,
      ruleId,
      recommendationTitle,
      requestedBy,
      requestReason,
    } = validation.data;

    const [account, identity] = await Promise.all([
      prisma.cloudAccount.findUnique({
        where: { id: cloudAccountId },
        select: { id: true },
      }),
      prisma.cloudIdentity.findFirst({
        where: {
          id: cloudIdentityId,
          cloudAccountId,
        },
        select: { id: true },
      }),
    ]);

    if (!account) {
      return res.status(404).json({
        error: "Cloud account not found.",
      });
    }

    if (!identity) {
      return res.status(404).json({
        error: "Cloud identity not found in this cloud account.",
      });
    }

    const approval = await prisma.iamRemediationApproval.create({
      data: {
        cloudAccountId,
        cloudIdentityId,
        ruleId,
        recommendationTitle,
        requestedBy,
        requestReason,
      },
    });

    return res.status(201).json({
      message: "Remediation approval request created successfully.",
      approval,
    });
  } catch (error) {
    console.error("Failed to create remediation approval:", error);

    return res.status(500).json({
      error: "Unable to create remediation approval request.",
    });
  }
});
// GET /api/iam/approvals?cloudAccountId=...
router.get("/approvals", async (req, res) => {
  const validation = accountQuerySchema.safeParse(req.query);

  if (!validation.success) {
    return res.status(400).json({
      error: "A valid cloudAccountId is required.",
    });
  }

  try {
    const approvals = await prisma.iamRemediationApproval.findMany({
      where: {
        cloudAccountId: validation.data.cloudAccountId,
      },
      include: {
        cloudIdentity: {
          select: {
            id: true,
            displayName: true,
            identityType: true,
          },
        },
      },
      orderBy: {
        requestedAt: "desc",
      },
    });

    return res.status(200).json({
      approvals,
      total: approvals.length,
    });
  } catch (error) {
    console.error("Failed to retrieve remediation approvals:", error);

    return res.status(500).json({
      error: "Unable to retrieve remediation approvals.",
    });
  }
});

// PATCH /api/iam/approvals/:id/decision
router.patch("/approvals/:id/decision", async (req, res) => {
  const idValidation = accountIdSchema.safeParse(req.params.id);
  const bodyValidation = approvalDecisionSchema.safeParse(req.body);

  if (!idValidation.success || !bodyValidation.success) {
    return res.status(400).json({
      error: "Invalid approval decision request.",
    });
  }

  try {
    const { action, reviewedBy, reviewComment } = bodyValidation.data;

    const result = await prisma.$transaction(async (tx) => {
      const approval = await tx.iamRemediationApproval.findUnique({
        where: { id: idValidation.data },
      });

      if (!approval) {
        return { type: "NOT_FOUND" as const };
      }

      if (approval.status !== "PENDING") {
        return { type: "CONFLICT" as const };
      }

      if (approval.requestedBy === reviewedBy) {
        return { type: "SELF_REVIEW" as const };
      }

      const updated = await tx.iamRemediationApproval.updateMany({
        where: {
          id: idValidation.data,
          status: "PENDING",
        },
        data: {
          status: action === "APPROVE" ? "APPROVED" : "REJECTED",
          reviewedBy,
          reviewComment: reviewComment ?? null,
          reviewedAt: new Date(),
        },
      });

      if (updated.count !== 1) {
        return { type: "CONFLICT" as const };
      }

      const updatedApproval = await tx.iamRemediationApproval.findUnique({
        where: { id: idValidation.data },
        include: {
          cloudIdentity: {
            select: {
              id: true,
              displayName: true,
              identityType: true,
            },
          },
        },
      });

      return {
        type: "SUCCESS" as const,
        approval: updatedApproval,
      };
    });

    if (result.type === "NOT_FOUND") {
      return res.status(404).json({
        error: "Approval request not found.",
      });
    }

    if (result.type === "CONFLICT") {
      return res.status(409).json({
        error: "This approval request has already been decided or cancelled.",
      });
    }

    if (result.type === "SELF_REVIEW") {
      return res.status(403).json({
        error: "Requesters cannot review their own approval requests.",
      });
    }

    return res.status(200).json({
      message: `Approval request ${action === "APPROVE" ? "approved" : "rejected"} successfully.`,
      approval: result.approval,
    });
  } catch (error) {
    console.error("Failed to process approval decision:", error);

    return res.status(500).json({
      error: "Unable to process approval decision.",
    });
  }
});

// POST /api/iam/approvals/:id/verifications
router.post("/approvals/:id/verifications", async (req, res) => {
  const idValidation = accountIdSchema.safeParse(req.params.id);
  const bodyValidation = createVerificationSchema.safeParse(req.body);

  if (!idValidation.success || !bodyValidation.success) {
    return res.status(400).json({
      error: "Invalid remediation verification request.",
    });
  }

  try {
    const approval = await prisma.iamRemediationApproval.findUnique({
      where: { id: idValidation.data },
    });

    if (!approval) {
      return res.status(404).json({
        error: "Approval request not found.",
      });
    }

    if (approval.status !== "APPROVED") {
      return res.status(409).json({
        error: "Only approved remediation requests can be verified.",
      });
    }

    const verification = await prisma.iamRemediationVerification.create({
      data: {
        approvalId: approval.id,
        verifiedBy: bodyValidation.data.verifiedBy,
        evidence: bodyValidation.data.evidence,
        notes: bodyValidation.data.notes,
      },
    });

    return res.status(201).json({
      message: "Remediation verification record created successfully.",
      verification,
    });
  } catch (error) {
    console.error("Failed to create remediation verification:", error);

    return res.status(500).json({
      error: "Unable to create remediation verification record.",
    });
  }
});

// GET /api/iam/approvals/:id/verifications
router.get("/approvals/:id/verifications", async (req, res) => {
  const idValidation = accountIdSchema.safeParse(req.params.id);

  if (!idValidation.success) {
    return res.status(400).json({
      error: "Invalid approval request ID.",
    });
  }

  try {
    const approval = await prisma.iamRemediationApproval.findUnique({
      where: { id: idValidation.data },
      select: { id: true },
    });

    if (!approval) {
      return res.status(404).json({
        error: "Approval request not found.",
      });
    }

    const verifications = await prisma.iamRemediationVerification.findMany({
      where: {
        approvalId: approval.id,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    return res.status(200).json({
      verifications,
      total: verifications.length,
    });
  } catch (error) {
    console.error("Failed to retrieve verification history:", error);

    return res.status(500).json({
      error: "Unable to retrieve verification history.",
    });
  }
});

// PATCH /api/iam/verifications/:id
router.patch("/verifications/:id", async (req, res) => {
  const idValidation = accountIdSchema.safeParse(req.params.id);
  const bodyValidation = updateVerificationSchema.safeParse(req.body);

  if (!idValidation.success || !bodyValidation.success) {
    return res.status(400).json({
      error: "Invalid verification update request.",
    });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      const verification = await tx.iamRemediationVerification.findUnique({
        where: { id: idValidation.data },
      });

      if (!verification) {
        return { type: "NOT_FOUND" as const };
      }

      if (verification.status !== "PENDING") {
        return { type: "CONFLICT" as const };
      }

      const updated = await tx.iamRemediationVerification.updateMany({
        where: {
          id: idValidation.data,
          status: "PENDING",
        },
        data: {
          status: bodyValidation.data.status,
          evidence: bodyValidation.data.evidence,
          notes: bodyValidation.data.notes,
          verifiedAt: new Date(),
        },
      });

      if (updated.count !== 1) {
        return { type: "CONFLICT" as const };
      }

      const updatedVerification =
        await tx.iamRemediationVerification.findUnique({
          where: { id: idValidation.data },
        });

      return {
        type: "SUCCESS" as const,
        verification: updatedVerification,
      };
    });

    if (result.type === "NOT_FOUND") {
      return res.status(404).json({
        error: "Verification record not found.",
      });
    }

    if (result.type === "CONFLICT") {
      return res.status(409).json({
        error: "Only pending verification records can be updated.",
      });
    }

    return res.status(200).json({
      message: "Remediation verification updated successfully.",
      verification: result.verification,
    });
  } catch (error) {
    console.error("Failed to update remediation verification:", error);

    return res.status(500).json({
      error: "Unable to update remediation verification.",
    });
  }
});

// PATCH /api/iam/approvals/:id/cancel
router.patch("/approvals/:id/cancel", async (req, res) => {
  const idValidation = accountIdSchema.safeParse(req.params.id);

  const requesterValidation = z
    .object({
      requestedBy: z.string().min(1).max(100),
    })
    .safeParse(req.body);

  if (!idValidation.success || !requesterValidation.success) {
    return res.status(400).json({
      error: "Invalid approval cancellation request.",
    });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      const approval = await tx.iamRemediationApproval.findUnique({
        where: { id: idValidation.data },
      });

      if (!approval) {
        return { type: "NOT_FOUND" as const };
      }

      if (approval.requestedBy !== requesterValidation.data.requestedBy) {
        return { type: "FORBIDDEN" as const };
      }

      if (approval.status !== "PENDING") {
        return { type: "CONFLICT" as const };
      }

      const updated = await tx.iamRemediationApproval.updateMany({
        where: {
          id: idValidation.data,
          status: "PENDING",
          requestedBy: requesterValidation.data.requestedBy,
        },
        data: {
          status: "CANCELLED",
          cancelledAt: new Date(),
        },
      });

      if (updated.count !== 1) {
        return { type: "CONFLICT" as const };
      }

      return {
        type: "SUCCESS" as const,
        approval: await tx.iamRemediationApproval.findUnique({
          where: { id: idValidation.data },
        }),
      };
    });

    if (result.type === "NOT_FOUND") {
      return res.status(404).json({
        error: "Approval request not found.",
      });
    }

    if (result.type === "FORBIDDEN") {
      return res.status(403).json({
        error: "Only the original requester can cancel this request.",
      });
    }

    if (result.type === "CONFLICT") {
      return res.status(409).json({
        error: "Only pending approval requests can be cancelled.",
      });
    }

    return res.status(200).json({
      message: "Approval request cancelled successfully.",
      approval: result.approval,
    });
  } catch (error) {
    console.error("Failed to cancel approval request:", error);

    return res.status(500).json({
      error: "Unable to cancel approval request.",
    });
  }
});
export default router;
