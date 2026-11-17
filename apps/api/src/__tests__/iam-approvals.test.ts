import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { prismaMock } = vi.hoisted(() => ({
  prismaMock: {
    cloudAccount: {
      findUnique: vi.fn(),
    },
    cloudIdentity: {
      findFirst: vi.fn(),
    },
    iamRemediationApproval: {
      create: vi.fn(),
      findMany: vi.fn(),
      findUnique: vi.fn(),
      updateMany: vi.fn(),
    },
    iamRemediationVerification: {
      create: vi.fn(),
      findMany: vi.fn(),
      findUnique: vi.fn(),
      updateMany: vi.fn(),
    },
    $transaction: vi.fn(),
  },
}));

vi.mock("../db.js", () => ({
  prisma: prismaMock,
}));

import iamRouter from "../routes/iam.js";

const app = express();
app.use(express.json());
app.use("/api/iam", iamRouter);

describe("IAM Remediation Approval API", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    prismaMock.cloudAccount.findUnique.mockResolvedValue({
      id: "11111111-1111-4111-8111-111111111111",
    });

    prismaMock.cloudIdentity.findFirst.mockResolvedValue({
      id: "22222222-2222-4222-8222-222222222222",
    });

    prismaMock.iamRemediationApproval.create.mockResolvedValue({});
    prismaMock.iamRemediationApproval.findMany.mockResolvedValue([]);
    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue(null);
    prismaMock.iamRemediationApproval.updateMany.mockResolvedValue({
      count: 1,
    });

    prismaMock.$transaction.mockImplementation(
      async (callback: (transaction: typeof prismaMock) => Promise<unknown>) =>
        callback(prismaMock),
    );
  });
  it("should create a remediation approval request", async () => {
    const approval = {
      id: "33333333-3333-4333-8333-333333333333",
      cloudAccountId: "11111111-1111-4111-8111-111111111111",
      cloudIdentityId: "22222222-2222-4222-8222-222222222222",
      ruleId: "IAM-AZ-001",
      recommendationTitle: "Remove excessive permissions",
      requestedBy: "demo-requester",
      requestReason: "Requesting approval to reduce excessive IAM permissions.",
      status: "PENDING",
    };

    prismaMock.iamRemediationApproval.create.mockResolvedValue(approval);

    const response = await request(app)
      .post("/api/iam/approvals")
      .send({
        cloudAccountId: approval.cloudAccountId,
        cloudIdentityId: approval.cloudIdentityId,
        ruleId: approval.ruleId,
        recommendationTitle: approval.recommendationTitle,
        requestedBy: approval.requestedBy,
        requestReason: approval.requestReason,
      })
      .expect(201);

    expect(response.body.approval).toMatchObject({
      id: approval.id,
      status: "PENDING",
      ruleId: "IAM-AZ-001",
    });

    expect(prismaMock.iamRemediationApproval.create).toHaveBeenCalledTimes(1);
  });
  it("should reject a request when the cloud identity does not belong to the account", async () => {
    prismaMock.cloudIdentity.findFirst.mockResolvedValue(null);

    const response = await request(app)
      .post("/api/iam/approvals")
      .send({
        cloudAccountId: "11111111-1111-4111-8111-111111111111",
        cloudIdentityId: "22222222-2222-4222-8222-222222222222",
        ruleId: "IAM-AZ-001",
        recommendationTitle: "Remove excessive permissions",
        requestedBy: "demo-requester",
        requestReason:
          "Requesting approval to reduce excessive IAM permissions.",
      })
      .expect(404);

    expect(response.body.error).toBe(
      "Cloud identity not found in this cloud account.",
    );
    expect(prismaMock.iamRemediationApproval.create).not.toHaveBeenCalled();
  });
  it("should reject a request with an invalid reason", async () => {
    const response = await request(app)
      .post("/api/iam/approvals")
      .send({
        cloudAccountId: "11111111-1111-4111-8111-111111111111",
        cloudIdentityId: "22222222-2222-4222-8222-222222222222",
        ruleId: "IAM-AZ-001",
        recommendationTitle: "Remove excessive permissions",
        requestedBy: "demo-requester",
        requestReason: "Too short",
      })
      .expect(400);

    expect(prismaMock.iamRemediationApproval.create).not.toHaveBeenCalled();
  });
  it("should reject a request when the cloud account does not exist", async () => {
    prismaMock.cloudAccount.findUnique.mockResolvedValue(null);

    const response = await request(app)
      .post("/api/iam/approvals")
      .send({
        cloudAccountId: "11111111-1111-4111-8111-111111111111",
        cloudIdentityId: "22222222-2222-4222-8222-222222222222",
        ruleId: "IAM-AZ-001",
        recommendationTitle: "Remove excessive permissions",
        requestedBy: "demo-requester",
        requestReason:
          "Requesting approval to reduce excessive IAM permissions.",
      })
      .expect(404);

    expect(response.body.error).toBe("Cloud account not found.");
    expect(prismaMock.iamRemediationApproval.create).not.toHaveBeenCalled();
  });
  it("should list approval requests for a cloud account", async () => {
    const approvals = [
      {
        id: "33333333-3333-4333-8333-333333333333",
        cloudAccountId: "11111111-1111-4111-8111-111111111111",
        cloudIdentityId: "22222222-2222-4222-8222-222222222222",
        ruleId: "IAM-AZ-001",
        recommendationTitle: "Remove excessive permissions",
        requestedBy: "demo-requester",
        requestReason:
          "Requesting approval to reduce excessive IAM permissions.",
        status: "PENDING",
        cloudIdentity: {
          id: "22222222-2222-4222-8222-222222222222",
          displayName: "Demo Identity",
          identityType: "SERVICE_PRINCIPAL",
        },
      },
    ];

    prismaMock.iamRemediationApproval.findMany.mockResolvedValue(approvals);

    const response = await request(app)
      .get("/api/iam/approvals")
      .query({
        cloudAccountId: "11111111-1111-4111-8111-111111111111",
      })
      .expect(200);

    expect(response.body.total).toBe(1);
    expect(response.body.approvals).toHaveLength(1);
    expect(response.body.approvals[0].status).toBe("PENDING");
    expect(response.body.approvals[0].cloudIdentity.displayName).toBe(
      "Demo Identity",
    );
  });
  it("should approve a pending remediation request", async () => {
    const approval = {
      id: "33333333-3333-4333-8333-333333333333",
      cloudAccountId: "11111111-1111-4111-8111-111111111111",
      cloudIdentityId: "22222222-2222-4222-8222-222222222222",
      ruleId: "IAM-AZ-001",
      recommendationTitle: "Remove excessive permissions",
      requestedBy: "demo-requester",
      reviewedBy: "demo-reviewer",
      requestReason: "Requesting approval to reduce excessive IAM permissions.",
      reviewComment: "Approved after reviewing the recommendation.",
      status: "PENDING",
    };

    const updatedApproval = {
      ...approval,
      status: "APPROVED",
      reviewedAt: new Date().toISOString(),
      cloudIdentity: {
        id: approval.cloudIdentityId,
        displayName: "Demo Identity",
        identityType: "SERVICE_PRINCIPAL",
      },
    };

    prismaMock.iamRemediationApproval.findUnique
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(updatedApproval);

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/decision`)
      .send({
        action: "APPROVE",
        reviewedBy: "demo-reviewer",
        reviewComment: "Approved after reviewing the recommendation.",
      })
      .expect(200);

    expect(response.body.approval.status).toBe("APPROVED");
    expect(response.body.approval.reviewedBy).toBe("demo-reviewer");

    expect(prismaMock.iamRemediationApproval.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: approval.id,
          status: "PENDING",
        },
        data: expect.objectContaining({
          status: "APPROVED",
          reviewedBy: "demo-reviewer",
        }),
      }),
    );
  });
  it("should reject a pending remediation request", async () => {
    const approval = {
      id: "44444444-4444-4444-8444-444444444444",
      requestedBy: "demo-requester",
      status: "PENDING",
    };

    const updatedApproval = {
      ...approval,
      status: "REJECTED",
      reviewedBy: "demo-reviewer",
      reviewComment: "Insufficient justification.",
    };

    prismaMock.iamRemediationApproval.findUnique
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(updatedApproval);

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/decision`)
      .send({
        action: "REJECT",
        reviewedBy: "demo-reviewer",
        reviewComment: "Insufficient justification.",
      })
      .expect(200);

    expect(response.body.approval.status).toBe("REJECTED");
    expect(response.body.approval.reviewedBy).toBe("demo-reviewer");

    expect(prismaMock.iamRemediationApproval.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: approval.id,
          status: "PENDING",
        },
        data: expect.objectContaining({
          status: "REJECTED",
          reviewedBy: "demo-reviewer",
        }),
      }),
    );
  });
  it("should prevent a requester from reviewing their own approval request", async () => {
    const approval = {
      id: "55555555-5555-4555-8555-555555555555",
      requestedBy: "demo-requester",
      status: "PENDING",
    };

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValueOnce(
      approval,
    );

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/decision`)
      .send({
        action: "APPROVE",
        reviewedBy: "demo-requester",
        reviewComment: "Self-review attempt.",
      })
      .expect(403);

    expect(response.body.error).toBe(
      "Requesters cannot review their own approval requests.",
    );

    expect(prismaMock.iamRemediationApproval.updateMany).not.toHaveBeenCalled();
  });
  it("should return 404 when the approval request does not exist", async () => {
    prismaMock.iamRemediationApproval.findUnique.mockResolvedValueOnce(null);

    const response = await request(app)
      .patch("/api/iam/approvals/66666666-6666-4666-8666-666666666666/decision")
      .send({
        action: "APPROVE",
        reviewedBy: "demo-reviewer",
      })
      .expect(404);

    expect(response.body.error).toBe("Approval request not found.");

    expect(prismaMock.iamRemediationApproval.updateMany).not.toHaveBeenCalled();
  });
  it("should prevent a decision on an already reviewed request", async () => {
    const approval = {
      id: "77777777-7777-4777-8777-777777777777",
      requestedBy: "demo-requester",
      status: "APPROVED",
    };

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValueOnce(
      approval,
    );

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/decision`)
      .send({
        action: "REJECT",
        reviewedBy: "demo-reviewer",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "This approval request has already been decided or cancelled.",
    );

    expect(prismaMock.iamRemediationApproval.updateMany).not.toHaveBeenCalled();
  });
  it("should prevent concurrent decisions on the same approval request", async () => {
    const approval = {
      id: "88888888-8888-4888-8888-888888888888",
      requestedBy: "demo-requester",
      status: "PENDING",
    };

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValueOnce(
      approval,
    );

    prismaMock.iamRemediationApproval.updateMany.mockResolvedValueOnce({
      count: 0,
    });

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/decision`)
      .send({
        action: "APPROVE",
        reviewedBy: "demo-reviewer",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "This approval request has already been decided or cancelled.",
    );

    expect(prismaMock.iamRemediationApproval.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: approval.id,
          status: "PENDING",
        },
      }),
    );
  });
  it("should allow the requester to cancel a pending approval request", async () => {
    const approval = {
      id: "99999999-9999-4999-8999-999999999999",
      requestedBy: "demo-requester",
      status: "PENDING",
    };

    const updatedApproval = {
      ...approval,
      status: "CANCELLED",
    };

    prismaMock.iamRemediationApproval.findUnique
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(updatedApproval);

    prismaMock.iamRemediationApproval.updateMany.mockResolvedValueOnce({
      count: 1,
    });

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/cancel`)
      .send({
        requestedBy: "demo-requester",
      })
      .expect(200);

    expect(response.body.approval.status).toBe("CANCELLED");

    expect(prismaMock.iamRemediationApproval.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: approval.id,
          status: "PENDING",
          requestedBy: "demo-requester",
        },
        data: expect.objectContaining({
          status: "CANCELLED",
        }),
      }),
    );
  });
  it("should prevent another user from cancelling an approval request", async () => {
    const approval = {
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      requestedBy: "demo-requester",
      status: "PENDING",
    };

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValueOnce(
      approval,
    );

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/cancel`)
      .send({
        requestedBy: "another-user",
      })
      .expect(403);

    expect(response.body.error).toBe(
      "Only the original requester can cancel this request.",
    );

    expect(prismaMock.iamRemediationApproval.updateMany).not.toHaveBeenCalled();
  });
  it("should prevent cancellation of an already decided request", async () => {
    const approval = {
      id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      requestedBy: "demo-requester",
      status: "APPROVED",
    };

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValueOnce(
      approval,
    );

    const response = await request(app)
      .patch(`/api/iam/approvals/${approval.id}/cancel`)
      .send({
        requestedBy: "demo-requester",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "Only pending approval requests can be cancelled.",
    );

    expect(prismaMock.iamRemediationApproval.updateMany).not.toHaveBeenCalled();
  });
  it("should create a verification record for an approved request", async () => {
    const approvalId = "33333333-3333-4333-8333-333333333333";

    const verification = {
      id: "44444444-4444-4444-8444-444444444444",
      approvalId,
      verifiedBy: "demo-verifier",
      status: "PENDING",
      evidence: "Cloud configuration checked.",
      notes: "Ready for verification.",
    };

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue({
      id: approvalId,
      status: "APPROVED",
    });

    prismaMock.iamRemediationVerification.create.mockResolvedValue(
      verification,
    );

    const response = await request(app)
      .post(`/api/iam/approvals/${approvalId}/verifications`)
      .send({
        verifiedBy: "demo-verifier",
        evidence: "Cloud configuration checked.",
        notes: "Ready for verification.",
      })
      .expect(201);

    expect(response.body.verification).toMatchObject({
      id: verification.id,
      approvalId,
      status: "PENDING",
    });

    expect(prismaMock.iamRemediationVerification.create).toHaveBeenCalledTimes(
      1,
    );
  });
  it("should reject verification for a pending approval request", async () => {
    const approvalId = "33333333-3333-4333-8333-333333333333";

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue({
      id: approvalId,
      status: "PENDING",
    });

    const response = await request(app)
      .post(`/api/iam/approvals/${approvalId}/verifications`)
      .send({
        verifiedBy: "demo-verifier",
        evidence: "Configuration checked.",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "Only approved remediation requests can be verified.",
    );

    expect(prismaMock.iamRemediationVerification.create).not.toHaveBeenCalled();
  });

  it("should reject verification for a rejected approval request", async () => {
    const approvalId = "33333333-3333-4333-8333-333333333333";

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue({
      id: approvalId,
      status: "REJECTED",
    });

    const response = await request(app)
      .post(`/api/iam/approvals/${approvalId}/verifications`)
      .send({
        verifiedBy: "demo-verifier",
        evidence: "Configuration checked.",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "Only approved remediation requests can be verified.",
    );

    expect(prismaMock.iamRemediationVerification.create).not.toHaveBeenCalled();
  });

  it("should return 404 when the approval request does not exist", async () => {
    const approvalId = "33333333-3333-4333-8333-333333333333";

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue(null);

    const response = await request(app)
      .post(`/api/iam/approvals/${approvalId}/verifications`)
      .send({
        verifiedBy: "demo-verifier",
        evidence: "Configuration checked.",
      })
      .expect(404);

    expect(response.body.error).toBe("Approval request not found.");

    expect(prismaMock.iamRemediationVerification.create).not.toHaveBeenCalled();
  });
  it("should retrieve verification history for an approval request", async () => {
    const approvalId = "33333333-3333-4333-8333-333333333333";

    const verifications = [
      {
        id: "44444444-4444-4444-8444-444444444444",
        approvalId,
        verifiedBy: "demo-verifier",
        status: "SUCCESSFUL",
        evidence: "Permissions successfully reviewed.",
      },
      {
        id: "55555555-5555-4555-8555-555555555555",
        approvalId,
        verifiedBy: "demo-verifier",
        status: "FAILED",
        evidence: "Excessive permissions remain.",
      },
    ];

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue({
      id: approvalId,
    });

    prismaMock.iamRemediationVerification.findMany.mockResolvedValue(
      verifications,
    );

    const response = await request(app)
      .get(`/api/iam/approvals/${approvalId}/verifications`)
      .expect(200);

    expect(response.body.total).toBe(2);
    expect(response.body.verifications).toHaveLength(2);
    expect(response.body.verifications[0].status).toBe("SUCCESSFUL");

    expect(
      prismaMock.iamRemediationVerification.findMany,
    ).toHaveBeenCalledTimes(1);
  });

  it("should return 404 when the approval does not exist in verification history", async () => {
    const approvalId = "33333333-3333-4333-8333-333333333333";

    prismaMock.iamRemediationApproval.findUnique.mockResolvedValue(null);

    const response = await request(app)
      .get(`/api/iam/approvals/${approvalId}/verifications`)
      .expect(404);

    expect(response.body.error).toBe("Approval request not found.");

    expect(
      prismaMock.iamRemediationVerification.findMany,
    ).not.toHaveBeenCalled();
  });
  it("should mark a pending verification as successful", async () => {
    const verificationId = "44444444-4444-4444-8444-444444444444";
    const approvalId = "33333333-3333-4333-8333-333333333333";

    const pendingVerification = {
      id: verificationId,
      approvalId,
      verifiedBy: "demo-verifier",
      status: "PENDING",
    };

    const updatedVerification = {
      ...pendingVerification,
      status: "SUCCESSFUL",
      evidence: "Cloud permissions checked and corrected.",
      notes: "Verification completed successfully.",
      verifiedAt: new Date(),
    };

    prismaMock.iamRemediationVerification.findUnique
      .mockResolvedValueOnce(pendingVerification)
      .mockResolvedValueOnce(updatedVerification);

    prismaMock.iamRemediationVerification.updateMany.mockResolvedValue({
      count: 1,
    });

    const response = await request(app)
      .patch(`/api/iam/verifications/${verificationId}`)
      .send({
        status: "SUCCESSFUL",
        evidence: "Cloud permissions checked and corrected.",
        notes: "Verification completed successfully.",
      })
      .expect(200);

    expect(response.body.verification.status).toBe("SUCCESSFUL");

    expect(
      prismaMock.iamRemediationVerification.updateMany,
    ).toHaveBeenCalledTimes(1);
  });

  it("should mark a pending verification as failed", async () => {
    const verificationId = "44444444-4444-4444-8444-444444444444";
    const approvalId = "33333333-3333-4333-8333-333333333333";

    const pendingVerification = {
      id: verificationId,
      approvalId,
      verifiedBy: "demo-verifier",
      status: "PENDING",
    };

    const updatedVerification = {
      ...pendingVerification,
      status: "FAILED",
      evidence: "The excessive permissions still exist.",
      notes: "Remediation requires further action.",
      verifiedAt: new Date(),
    };

    prismaMock.iamRemediationVerification.findUnique
      .mockResolvedValueOnce(pendingVerification)
      .mockResolvedValueOnce(updatedVerification);

    prismaMock.iamRemediationVerification.updateMany.mockResolvedValue({
      count: 1,
    });

    const response = await request(app)
      .patch(`/api/iam/verifications/${verificationId}`)
      .send({
        status: "FAILED",
        evidence: "The excessive permissions still exist.",
        notes: "Remediation requires further action.",
      })
      .expect(200);

    expect(response.body.verification.status).toBe("FAILED");

    expect(
      prismaMock.iamRemediationVerification.updateMany,
    ).toHaveBeenCalledTimes(1);
  });

  it("should return 404 when the verification does not exist", async () => {
    const verificationId = "44444444-4444-4444-8444-444444444444";

    prismaMock.iamRemediationVerification.findUnique.mockResolvedValue(null);

    const response = await request(app)
      .patch(`/api/iam/verifications/${verificationId}`)
      .send({
        status: "SUCCESSFUL",
      })
      .expect(404);

    expect(response.body.error).toBe("Verification record not found.");

    expect(
      prismaMock.iamRemediationVerification.updateMany,
    ).not.toHaveBeenCalled();
  });
  it("should reject updates to an already completed verification", async () => {
    const verificationId = "44444444-4444-4444-8444-444444444444";

    prismaMock.iamRemediationVerification.findUnique.mockResolvedValue({
      id: verificationId,
      status: "SUCCESSFUL",
    });

    const response = await request(app)
      .patch(`/api/iam/verifications/${verificationId}`)
      .send({
        status: "FAILED",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "Only pending verification records can be updated.",
    );

    expect(
      prismaMock.iamRemediationVerification.updateMany,
    ).not.toHaveBeenCalled();
  });

  it("should reject an update when another request has already completed the verification", async () => {
    const verificationId = "44444444-4444-4444-8444-444444444444";

    prismaMock.iamRemediationVerification.findUnique.mockResolvedValue({
      id: verificationId,
      status: "PENDING",
    });

    prismaMock.iamRemediationVerification.updateMany.mockResolvedValue({
      count: 0,
    });

    const response = await request(app)
      .patch(`/api/iam/verifications/${verificationId}`)
      .send({
        status: "SUCCESSFUL",
      })
      .expect(409);

    expect(response.body.error).toBe(
      "Only pending verification records can be updated.",
    );
  });
});
