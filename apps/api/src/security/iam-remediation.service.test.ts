import { describe, expect, it } from "vitest";
import {
  generateIamRemediationRecommendations,
} from "./iam-remediation.service.js";
import type { IamSecurityDetection } from "./iam.rules.js";

function createDetection(
  ruleId: string,
  severity: IamSecurityDetection["severity"] = "HIGH"
): IamSecurityDetection & { identityId: string } {
  return {
    ruleId,
    identityId: "test-identity-001",
    title: "Test IAM Detection",
    description: "Test detection description",
    severity,
    evidence: {},
    remediation: "Test remediation",
  };
}
describe("generateIamRemediationRecommendations", () => {
  it("generates recommendations for all four IAM rules", () => {
    const detections = [
      createDetection("IAM-AZ-001", "CRITICAL"),
      createDetection("IAM-AZ-002", "CRITICAL"),
      createDetection("IAM-AZ-003", "MEDIUM"),
      createDetection("IAM-AZ-004", "HIGH"),
    ];

    const recommendations =
      generateIamRemediationRecommendations(detections);

    expect(recommendations).toHaveLength(4);

    expect(recommendations.map((item) => item.ruleId)).toEqual([
      "IAM-AZ-001",
      "IAM-AZ-002",
      "IAM-AZ-003",
      "IAM-AZ-004",
    ]);
  });
  it("maps detection severity to recommendation priority", () => {
  const detections = [
    createDetection("IAM-AZ-001", "CRITICAL"),
    createDetection("IAM-AZ-002", "HIGH"),
    createDetection("IAM-AZ-003", "MEDIUM"),
    createDetection("IAM-AZ-004", "LOW"),
  ];

  const recommendations =
    generateIamRemediationRecommendations(detections);

  expect(recommendations.map((item) => item.priority)).toEqual([
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
  ]);
});
it("ignores unknown IAM rule IDs", () => {
  const detections = [
    createDetection("IAM-AZ-999", "HIGH"),
  ];

  const recommendations =
    generateIamRemediationRecommendations(detections);

  expect(recommendations).toHaveLength(0);
});
it("keeps all recommendations manual-only", () => {
  const detections = [
    createDetection("IAM-AZ-001"),
    createDetection("IAM-AZ-002"),
    createDetection("IAM-AZ-003"),
    createDetection("IAM-AZ-004"),
  ];

  const recommendations =
    generateIamRemediationRecommendations(detections);

  expect(
    recommendations.every(
      (item) => item.executionMode === "MANUAL"
    )
  ).toBe(true);
});
});