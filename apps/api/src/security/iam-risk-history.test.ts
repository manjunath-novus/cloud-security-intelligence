
import { describe, expect, it } from "vitest";
import { calculateIamRiskTrend } from "./iam-risk-history.js";

describe("calculateIamRiskTrend", () => {
  it("returns WORSENING when the latest score increases", () => {
    expect(calculateIamRiskTrend(80, 60)).toEqual({
      direction: "WORSENING",
      scoreChange: 20,
      latestScore: 80,
      previousScore: 60,
    });
  });

  it("returns IMPROVING when the latest score decreases", () => {
    expect(calculateIamRiskTrend(40, 70)).toEqual({
      direction: "IMPROVING",
      scoreChange: -30,
      latestScore: 40,
      previousScore: 70,
    });
  });

  it("returns STABLE when both scores are equal", () => {
    expect(calculateIamRiskTrend(100, 100)).toEqual({
      direction: "STABLE",
      scoreChange: 0,
      latestScore: 100,
      previousScore: 100,
    });
  });

  it("returns INSUFFICIENT_DATA when there is no previous score", () => {
    expect(calculateIamRiskTrend(75, null)).toEqual({
      direction: "INSUFFICIENT_DATA",
      scoreChange: null,
      latestScore: 75,
      previousScore: null,
    });
  });

  it("returns INSUFFICIENT_DATA when both scores are missing", () => {
    expect(calculateIamRiskTrend(null, null)).toEqual({
      direction: "INSUFFICIENT_DATA",
      scoreChange: null,
      latestScore: null,
      previousScore: null,
    });
  });
});
