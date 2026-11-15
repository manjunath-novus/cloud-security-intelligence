
export type IamRiskTrendDirection =
  | "IMPROVING"
  | "WORSENING"
  | "STABLE"
  | "INSUFFICIENT_DATA";

export type IamRiskTrend = {
  direction: IamRiskTrendDirection;
  scoreChange: number | null;
  latestScore: number | null;
  previousScore: number | null;
};

export function calculateIamRiskTrend(
  latestScore: number | null,
  previousScore: number | null,
): IamRiskTrend {
  if (latestScore === null || previousScore === null) {
    return {
      direction: "INSUFFICIENT_DATA",
      scoreChange: null,
      latestScore,
      previousScore,
    };
  }

  const scoreChange = latestScore - previousScore;

  return {
    direction:
      scoreChange > 0
        ? "WORSENING"
        : scoreChange < 0
          ? "IMPROVING"
          : "STABLE",
    scoreChange,
    latestScore,
    previousScore,
  };
}
