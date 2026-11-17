-- CreateEnum
CREATE TYPE "IamRemediationVerificationStatus" AS ENUM ('PENDING', 'SUCCESSFUL', 'FAILED');

-- CreateTable
CREATE TABLE "IamRemediationVerification" (
    "id" TEXT NOT NULL,
    "approvalId" TEXT NOT NULL,
    "verifiedBy" TEXT NOT NULL,
    "status" "IamRemediationVerificationStatus" NOT NULL DEFAULT 'PENDING',
    "evidence" TEXT,
    "notes" TEXT,
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IamRemediationVerification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IamRemediationVerification_approvalId_status_idx" ON "IamRemediationVerification"("approvalId", "status");

-- CreateIndex
CREATE INDEX "IamRemediationVerification_verifiedBy_idx" ON "IamRemediationVerification"("verifiedBy");

-- CreateIndex
CREATE INDEX "IamRemediationVerification_status_createdAt_idx" ON "IamRemediationVerification"("status", "createdAt");

-- AddForeignKey
ALTER TABLE "IamRemediationVerification" ADD CONSTRAINT "IamRemediationVerification_approvalId_fkey" FOREIGN KEY ("approvalId") REFERENCES "IamRemediationApproval"("id") ON DELETE CASCADE ON UPDATE CASCADE;
