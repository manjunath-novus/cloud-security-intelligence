-- CreateEnum
CREATE TYPE "IamRemediationApprovalStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "IamRemediationApprovalAction" AS ENUM ('APPROVE', 'REJECT');

-- CreateTable
CREATE TABLE "IamRemediationApproval" (
    "id" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "cloudIdentityId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "recommendationTitle" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL,
    "reviewedBy" TEXT,
    "status" "IamRemediationApprovalStatus" NOT NULL DEFAULT 'PENDING',
    "requestReason" TEXT NOT NULL,
    "reviewComment" TEXT,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewedAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IamRemediationApproval_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IamRemediationApproval_cloudAccountId_status_idx" ON "IamRemediationApproval"("cloudAccountId", "status");

-- CreateIndex
CREATE INDEX "IamRemediationApproval_cloudIdentityId_idx" ON "IamRemediationApproval"("cloudIdentityId");

-- CreateIndex
CREATE INDEX "IamRemediationApproval_requestedBy_idx" ON "IamRemediationApproval"("requestedBy");

-- CreateIndex
CREATE INDEX "IamRemediationApproval_reviewedBy_idx" ON "IamRemediationApproval"("reviewedBy");

-- CreateIndex
CREATE INDEX "IamRemediationApproval_status_requestedAt_idx" ON "IamRemediationApproval"("status", "requestedAt");

-- AddForeignKey
ALTER TABLE "IamRemediationApproval" ADD CONSTRAINT "IamRemediationApproval_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IamRemediationApproval" ADD CONSTRAINT "IamRemediationApproval_cloudIdentityId_fkey" FOREIGN KEY ("cloudIdentityId") REFERENCES "CloudIdentity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
