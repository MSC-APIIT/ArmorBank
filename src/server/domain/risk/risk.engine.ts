export type RiskContext = {
  ip: string;
  deviceId: string;
  isNewDevice: boolean;
  isNewIp: boolean;
  deviceTrust: "unknown" | "trusted" | "risky" | "blocked";
  recentFailures: number; // last X minutes
  geoChanged: boolean;
};

export type RiskResult = {
  score: number; // 0-100
  tier: "low" | "medium" | "high";
  triggeredRules: string[];
};

function clamp(n: number) {
  if (n < 0) return 0;
  if (n > 100) return 100;
  return n;
}

export function evaluateLoginRisk(ctx: RiskContext): RiskResult {
  let score = 0;
  const triggeredRules: string[] = [];

  if (ctx.isNewDevice) {
    score += 30;
    triggeredRules.push("NEW_DEVICE");
  }

  if (ctx.isNewIp) {
    score += 30;
    triggeredRules.push("NEW_IP");
  }

  if (ctx.deviceTrust === "risky") {
    score += 25;
    triggeredRules.push("RISKY_DEVICE");
  }

  if (ctx.deviceTrust === "blocked") {
    score += 100;
    triggeredRules.push("BLOCKED_DEVICE");
  }

  if (ctx.geoChanged) {
    score += 15;
    triggeredRules.push("GEO_CHANGED");
  }

  if (ctx.recentFailures >= 3) {
    score += 15;
    triggeredRules.push("FAILURE_VELOCITY_MEDIUM");
  }
  if (ctx.recentFailures >= 6) {
    score += 25;
    triggeredRules.push("FAILURE_VELOCITY_HIGH");
  }

  score = clamp(score);

  let tier: RiskResult["tier"] = "low";
  if (score >= 70) tier = "high";
  else if (score >= 30) tier = "medium";
  return { score, tier, triggeredRules };
}
