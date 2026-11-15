-- CreateTable
CREATE TABLE "IamRiskScan" (
    "id" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "rawRiskScore" INTEGER NOT NULL,
    "riskLevel" TEXT NOT NULL,
    "riskExposureCount" INTEGER NOT NULL,
    "detectedFindingCount" INTEGER NOT NULL,
    "severityBreakdown" JSONB NOT NULL,
    "severityPoints" JSONB NOT NULL,
    "identitiesScanned" INTEGER NOT NULL,
    "assignmentsScanned" INTEGER NOT NULL,
    "riskScoreWasCapped" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IamRiskScan_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IamRiskScan_cloudAccountId_createdAt_idx" ON "IamRiskScan"("cloudAccountId", "createdAt");

-- AddForeignKey
ALTER TABLE "IamRiskScan" ADD CONSTRAINT "IamRiskScan_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;
