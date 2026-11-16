import type { IamSecurityDetection } from "./iam.rules.js";

export type IamRemediationRecommendation = {
  ruleId: string;
  identityId: string;
  title: string;
  explanation: string;
  recommendedActions: string[];
  expectedImpact: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  executionMode: "MANUAL";
};
export function generateIamRemediationRecommendations(
  detections: (IamSecurityDetection & { identityId: string })[]
): IamRemediationRecommendation[] {
    return detections.flatMap<IamRemediationRecommendation>((detection) => {
    const priority =
      detection.severity === "CRITICAL" ||
      detection.severity === "HIGH" ||
      detection.severity === "MEDIUM"
        ? detection.severity
        : "LOW";

    switch (detection.ruleId) {
      case "IAM-AZ-001":
        return [{
          ruleId: detection.ruleId,
          identityId: detection.identityId,
          title: "Reduce Broad Subscription Permissions",
          explanation:
            "This identity has broad management permissions at subscription scope.",
          recommendedActions: [
            "Review whether subscription-wide access is necessary.",
            "Replace broad permissions with a least-privilege role.",
            "Restrict the assignment to the smallest required scope.",
            "Use time-bound privileged access where appropriate."
          ],
          expectedImpact:
            "Reduces excessive permissions and limits the potential impact of identity compromise.",
          priority,
          executionMode: "MANUAL"
        }];

      case "IAM-AZ-002":
        return [{
          ruleId: detection.ruleId,
          identityId: detection.identityId,
          title: "Reduce Workload Identity Permissions",
          explanation:
            "A workload identity has unrestricted subscription-level permissions.",
          recommendedActions: [
            "Review the workload's actual operational requirements.",
            "Assign only the minimum permissions required.",
            "Secure and rotate workload credentials where applicable.",
            "Monitor authentication and privileged operations."
          ],
          expectedImpact:
            "Limits workload identity privileges and reduces the risk of unauthorized cloud operations.",
          priority,
          executionMode: "MANUAL"
        }];

      case "IAM-AZ-003":
        return [{
          ruleId: detection.ruleId,
          identityId: detection.identityId,
          title: "Review Disabled Identity Assignments",
          explanation:
            "A disabled identity still retains a privileged role assignment.",
          recommendedActions: [
            "Verify the identity's owner and business requirement.",
            "Identify obsolete role assignments.",
            "Review other enabled identities or credentials that may provide equivalent access.",
            "Remove obsolete assignments only after approval."
          ],
          expectedImpact:
            "Reduces unnecessary privileged assignments and improves identity access hygiene.",
          priority,
          executionMode: "MANUAL"
        }];

      case "IAM-AZ-004":
        return [{
          ruleId: detection.ruleId,
          identityId: detection.identityId,
          title: "Restrict Role Assignment Management",
          explanation:
            "This identity has permissions to manage role assignments at subscription scope.",
          recommendedActions: [
            "Restrict role assignment management to trusted administrators.",
            "Review existing role assignment permissions.",
            "Narrow the assignment scope where possible.",
            "Monitor privileged permission changes."
          ],
          expectedImpact:
            "Reduces the risk of unauthorized privilege escalation and permission changes.",
          priority,
          executionMode: "MANUAL"
        }];

      default:
        return [];
    }
  });
}