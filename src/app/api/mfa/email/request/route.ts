import { NextResponse } from "next/server";
import nodemailer from "nodemailer";
import crypto from "crypto";
import { getDb } from "@/server/db/mongo";
import { env } from "@/server/config/env";

// Create transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: env.GMAIL_USER,
    pass: env.GMAIL_APP_PASSWORD,
  },
});

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export async function POST(req: Request) {
  try {
    const { mfaToken } = await req.json();

    if (!mfaToken) {
      return NextResponse.json(
        { message: "Missing mfaToken" },
        { status: 400 },
      );
    }

    const db = await getDb();
    const mfaChallenges = db.collection("mfa_challenges");
    const users = db.collection("users");

    const challenge = await mfaChallenges.findOne<any>({
      mfaTokenHash: sha256(mfaToken),
      status: "pending",
      expiresAt: { $gt: new Date() },
    });

    if (!challenge) {
      return NextResponse.json(
        { message: "Invalid or expired MFA token" },
        { status: 401 },
      );
    }

    const user = await users.findOne<any>({ _id: challenge.userId });
    if (!user || !user.email) {
      return NextResponse.json({ message: "User not found" }, { status: 404 });
    }

    const otp = generateOTP();
    const otpHash = sha256(otp);
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await mfaChallenges.updateOne(
      { _id: challenge._id },
      {
        $set: {
          emailOtpHash: otpHash,
          emailOtpExpiresAt: otpExpiresAt,
          emailOtpAttempts: 0,
        },
      },
    );

    // Send email with Nodemailer
    await transporter.sendMail({
      from: `"Bank-Auth - AuthArmor" <${env.GMAIL_USER}>`,
      to: user.email,
      subject: "Your verification code",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Verify your login</h2>
          <p>Your verification code is:</p>
          <div style="background: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 20px 0;">
            ${otp}
          </div>
          <p style="color: #666;">This code will expire in 5 minutes.</p>
          <p style="color: #666;">If you didn't request this code, please ignore this email.</p>
          <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
          <p style="color: #999; font-size: 12px;">This is an automated message, please do not reply.</p>
        </div>
      `,
    });

    console.log("==========================================");
    console.log("🔐 OTP CODE FOR TESTING:", otp);
    console.log("📧 Send to:", user.email);
    console.log("==========================================");

    return NextResponse.json({
      ok: true,
      message: "OTP sent to your email",
    });
  } catch (error) {
    console.error("Email OTP request error:", error);
    return NextResponse.json(
      { message: "Failed to send OTP" },
      { status: 500 },
    );
  }
}
