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
        callback(prismaMock)
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
      requestReason: "Requesting approval to reduce excessive IAM permissions.",
    })
    .expect(404);

  expect(response.body.error).toBe("Cloud identity not found in this cloud account.");
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
      requestReason: "Requesting approval to reduce excessive IAM permissions.",
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
      requestReason: "Requesting approval to reduce excessive IAM permissions.",
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
  expect(response.body.approvals[0].cloudIdentity.displayName).toBe("Demo Identity");
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
    })
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
    })
  );
});
it("should prevent a requester from reviewing their own approval request", async () => {
  const approval = {
    id: "55555555-5555-4555-8555-555555555555",
    requestedBy: "demo-requester",
    status: "PENDING",
  };

  prismaMock.iamRemediationApproval.findUnique
    .mockResolvedValueOnce(approval);

  const response = await request(app)
    .patch(`/api/iam/approvals/${approval.id}/decision`)
    .send({
      action: "APPROVE",
      reviewedBy: "demo-requester",
      reviewComment: "Self-review attempt.",
    })
    .expect(403);

  expect(response.body.error).toBe(
    "Requesters cannot review their own approval requests."
  );

  expect(prismaMock.iamRemediationApproval.updateMany)
    .not.toHaveBeenCalled();
});
it("should return 404 when the approval request does not exist", async () => {
  prismaMock.iamRemediationApproval.findUnique
    .mockResolvedValueOnce(null);

  const response = await request(app)
    .patch(
      "/api/iam/approvals/66666666-6666-4666-8666-666666666666/decision"
    )
    .send({
      action: "APPROVE",
      reviewedBy: "demo-reviewer",
    })
    .expect(404);

  expect(response.body.error).toBe(
    "Approval request not found."
  );

  expect(prismaMock.iamRemediationApproval.updateMany)
    .not.toHaveBeenCalled();
});
it("should prevent a decision on an already reviewed request", async () => {
  const approval = {
    id: "77777777-7777-4777-8777-777777777777",
    requestedBy: "demo-requester",
    status: "APPROVED",
  };

  prismaMock.iamRemediationApproval.findUnique
    .mockResolvedValueOnce(approval);

  const response = await request(app)
    .patch(`/api/iam/approvals/${approval.id}/decision`)
    .send({
      action: "REJECT",
      reviewedBy: "demo-reviewer",
    })
    .expect(409);

  expect(response.body.error).toBe(
  "This approval request has already been decided or cancelled."
);

  expect(prismaMock.iamRemediationApproval.updateMany)
    .not.toHaveBeenCalled();
});
it("should prevent concurrent decisions on the same approval request", async () => {
  const approval = {
    id: "88888888-8888-4888-8888-888888888888",
    requestedBy: "demo-requester",
    status: "PENDING",
  };

  prismaMock.iamRemediationApproval.findUnique
    .mockResolvedValueOnce(approval);

  prismaMock.iamRemediationApproval.updateMany
    .mockResolvedValueOnce({ count: 0 });

  const response = await request(app)
    .patch(`/api/iam/approvals/${approval.id}/decision`)
    .send({
      action: "APPROVE",
      reviewedBy: "demo-reviewer",
    })
    .expect(409);

  expect(response.body.error).toBe(
    "This approval request has already been decided or cancelled."
  );

  expect(prismaMock.iamRemediationApproval.updateMany)
    .toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: approval.id,
          status: "PENDING",
        },
      })
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

  prismaMock.iamRemediationApproval.updateMany
    .mockResolvedValueOnce({ count: 1 });

  const response = await request(app)
    .patch(`/api/iam/approvals/${approval.id}/cancel`)
    .send({
      requestedBy: "demo-requester",
    })
    .expect(200);

  expect(response.body.approval.status).toBe("CANCELLED");

  expect(prismaMock.iamRemediationApproval.updateMany)
    .toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: approval.id,
          status: "PENDING",
          requestedBy: "demo-requester",
        },
        data: expect.objectContaining({
          status: "CANCELLED",
        }),
      })
    );
});
it("should prevent another user from cancelling an approval request", async () => {
  const approval = {
    id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    requestedBy: "demo-requester",
    status: "PENDING",
  };

  prismaMock.iamRemediationApproval.findUnique
    .mockResolvedValueOnce(approval);

  const response = await request(app)
    .patch(`/api/iam/approvals/${approval.id}/cancel`)
    .send({
      requestedBy: "another-user",
    })
    .expect(403);

   expect(response.body.error).toBe(
  "Only the original requester can cancel this request."
);

  expect(prismaMock.iamRemediationApproval.updateMany)
    .not.toHaveBeenCalled();
});
it("should prevent cancellation of an already decided request", async () => {
  const approval = {
    id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    requestedBy: "demo-requester",
    status: "APPROVED",
  };

  prismaMock.iamRemediationApproval.findUnique
    .mockResolvedValueOnce(approval);

  const response = await request(app)
    .patch(`/api/iam/approvals/${approval.id}/cancel`)
    .send({
      requestedBy: "demo-requester",
    })
    .expect(409);

  expect(response.body.error).toBe(
    "Only pending approval requests can be cancelled."
  );

  expect(prismaMock.iamRemediationApproval.updateMany)
    .not.toHaveBeenCalled();
});
});