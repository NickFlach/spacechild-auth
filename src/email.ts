/**
 * Email Service
 * 
 * Handles sending verification emails, password reset emails, and welcome emails.
 * Uses nodemailer with configurable SMTP settings.
 * Updated for SpaceChild Auth standalone service.
 */

import nodemailer from "nodemailer";

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@spacechild.love";
const APP_NAME = "SpaceChild Auth";

function getAppUrl(): string {
  if (process.env.NODE_ENV === "production") {
    return process.env.APP_URL || "https://auth.spacechild.love";
  }
  return process.env.APP_URL || "http://localhost:3100";
}

const MASCOT_IMAGE_URL = "https://spacechild.love/mascot-email.png";

function createTransport() {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    console.warn("Email service not configured - SMTP credentials missing");
    return null;
  }
  
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
}

const transporter = createTransport();

export async function sendVerificationEmail(email: string, token: string, firstName?: string): Promise<boolean> {
  if (!transporter) {
    console.log(`[DEV MODE] Verification email for ${email}: ${getAppUrl()}/verify-email?token=${token}`);
    return true;
  }

  const verifyUrl = `${getAppUrl()}/verify-email?token=${token}`;
  const name = firstName || "Explorer";

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Verify Your Email - ${APP_NAME}</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
          }
          .email-container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .mascot {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin-bottom: 20px;
          }
          .title {
            color: #1a1a1a;
            font-size: 28px;
            font-weight: 700;
            margin: 0 0 10px 0;
          }
          .subtitle {
            color: #666;
            font-size: 16px;
            margin: 0;
          }
          .content {
            margin: 30px 0;
          }
          .button {
            display: inline-block;
            padding: 16px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            text-align: center;
            margin: 20px 0;
            transition: transform 0.2s ease;
          }
          .button:hover {
            transform: translateY(-2px);
          }
          .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #666;
            font-size: 14px;
          }
          .link-fallback {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            <img src="${MASCOT_IMAGE_URL}" alt="${APP_NAME} Mascot" class="mascot" />
            <h1 class="title">Welcome to ${APP_NAME}! 🚀</h1>
            <p class="subtitle">Verify your email to complete your registration</p>
          </div>

          <div class="content">
            <p>Hi ${name},</p>
            
            <p>Thanks for signing up for ${APP_NAME}! To complete your registration and start exploring, please verify your email address by clicking the button below:</p>
            
            <div style="text-align: center;">
              <a href="${verifyUrl}" class="button">Verify Email Address</a>
            </div>

            <p>This verification link will expire in 24 hours for security reasons.</p>

            <p><strong>If the button doesn't work</strong>, copy and paste this link into your browser:</p>
            <div class="link-fallback">${verifyUrl}</div>

            <p>If you didn't sign up for ${APP_NAME}, you can safely ignore this email.</p>
          </div>

          <div class="footer">
            <p>Best regards,<br />The ${APP_NAME} Team</p>
            <p style="margin-top: 20px; font-size: 12px;">
              This email was sent to ${email}. If you have any questions, please contact our support team.
            </p>
          </div>
        </div>
      </body>
    </html>
  `;

  const text = `
Welcome to ${APP_NAME}!

Hi ${name},

Thanks for signing up for ${APP_NAME}! To complete your registration, please verify your email address by visiting this link:

${verifyUrl}

This verification link will expire in 24 hours for security reasons.

If you didn't sign up for ${APP_NAME}, you can safely ignore this email.

Best regards,
The ${APP_NAME} Team
  `;

  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Welcome to ${APP_NAME} - Verify Your Email`,
      text,
      html,
    });
    
    console.log(`✅ Verification email sent to ${email}`);
    return true;
  } catch (error) {
    console.error("❌ Failed to send verification email:", error);
    return false;
  }
}

export async function sendPasswordResetEmail(email: string, token: string, firstName?: string): Promise<boolean> {
  if (!transporter) {
    console.log(`[DEV MODE] Password reset email for ${email}: ${getAppUrl()}/reset-password?token=${token}`);
    return true;
  }

  const resetUrl = `${getAppUrl()}/reset-password?token=${token}`;
  const name = firstName || "User";

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Reset Your Password - ${APP_NAME}</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
          }
          .email-container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .title {
            color: #1a1a1a;
            font-size: 28px;
            font-weight: 700;
            margin: 0 0 10px 0;
          }
          .subtitle {
            color: #666;
            font-size: 16px;
            margin: 0;
          }
          .content {
            margin: 30px 0;
          }
          .button {
            display: inline-block;
            padding: 16px 32px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            text-align: center;
            margin: 20px 0;
            transition: transform 0.2s ease;
          }
          .button:hover {
            transform: translateY(-2px);
          }
          .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
          }
          .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #666;
            font-size: 14px;
          }
          .link-fallback {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            <h1 class="title">Password Reset Request 🔐</h1>
            <p class="subtitle">Reset your ${APP_NAME} password</p>
          </div>

          <div class="content">
            <p>Hi ${name},</p>
            
            <p>We received a request to reset the password for your ${APP_NAME} account. Click the button below to set a new password:</p>
            
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>

            <div class="warning">
              <strong>⚠️ Important:</strong> This password reset link will expire in 15 minutes for security reasons.
            </div>

            <p><strong>If the button doesn't work</strong>, copy and paste this link into your browser:</p>
            <div class="link-fallback">${resetUrl}</div>

            <p><strong>If you didn't request this password reset</strong>, you can safely ignore this email. Your password will not be changed.</p>
          </div>

          <div class="footer">
            <p>Best regards,<br />The ${APP_NAME} Team</p>
            <p style="margin-top: 20px; font-size: 12px;">
              This email was sent to ${email}. If you have any questions, please contact our support team.
            </p>
          </div>
        </div>
      </body>
    </html>
  `;

  const text = `
Password Reset Request

Hi ${name},

We received a request to reset the password for your ${APP_NAME} account. Visit this link to set a new password:

${resetUrl}

⚠️ Important: This password reset link will expire in 15 minutes for security reasons.

If you didn't request this password reset, you can safely ignore this email. Your password will not be changed.

Best regards,
The ${APP_NAME} Team
  `;

  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Reset Your ${APP_NAME} Password`,
      text,
      html,
    });
    
    console.log(`✅ Password reset email sent to ${email}`);
    return true;
  } catch (error) {
    console.error("❌ Failed to send password reset email:", error);
    return false;
  }
}

export async function sendWelcomeEmail(email: string, firstName?: string): Promise<boolean> {
  if (!transporter) {
    console.log(`[DEV MODE] Welcome email for ${email}`);
    return true;
  }

  const name = firstName || "Explorer";
  const dashboardUrl = getAppUrl().replace('/auth', ''); // Remove /auth from URL for main app

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Welcome to ${APP_NAME}!</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
          }
          .email-container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .mascot {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin-bottom: 20px;
          }
          .title {
            color: #1a1a1a;
            font-size: 28px;
            font-weight: 700;
            margin: 0 0 10px 0;
          }
          .subtitle {
            color: #666;
            font-size: 16px;
            margin: 0;
          }
          .content {
            margin: 30px 0;
          }
          .button {
            display: inline-block;
            padding: 16px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            text-align: center;
            margin: 20px 0;
            transition: transform 0.2s ease;
          }
          .button:hover {
            transform: translateY(-2px);
          }
          .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #666;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            <img src="${MASCOT_IMAGE_URL}" alt="${APP_NAME} Mascot" class="mascot" />
            <h1 class="title">You're all set! 🎉</h1>
            <p class="subtitle">Welcome to the SpaceChild universe</p>
          </div>

          <div class="content">
            <p>Hi ${name},</p>
            
            <p>Congratulations! Your email has been verified and your ${APP_NAME} account is now active.</p>

            <p>You can now enjoy:</p>
            <ul>
              <li>🔐 <strong>Secure Authentication</strong> - Advanced ZKP and MFA support</li>
              <li>🚀 <strong>Single Sign-On</strong> - Access all SpaceChild services seamlessly</li>
              <li>🛡️ <strong>Privacy First</strong> - Your data stays yours</li>
              <li>🌟 <strong>Future-Ready</strong> - Built for the decentralized web</li>
            </ul>

            <div style="text-align: center;">
              <a href="${dashboardUrl}" class="button">Get Started</a>
            </div>

            <p>If you have any questions or need help getting started, don't hesitate to reach out to our support team.</p>
          </div>

          <div class="footer">
            <p>Welcome aboard! 🚀<br />The ${APP_NAME} Team</p>
            <p style="margin-top: 20px; font-size: 12px;">
              This email was sent to ${email}. You're receiving this because you just verified your SpaceChild account.
            </p>
          </div>
        </div>
      </body>
    </html>
  `;

  const text = `
Welcome to ${APP_NAME}!

Hi ${name},

Congratulations! Your email has been verified and your ${APP_NAME} account is now active.

You can now enjoy:
- 🔐 Secure Authentication - Advanced ZKP and MFA support  
- 🚀 Single Sign-On - Access all SpaceChild services seamlessly
- 🛡️ Privacy First - Your data stays yours
- 🌟 Future-Ready - Built for the decentralized web

Get started: ${dashboardUrl}

If you have any questions or need help getting started, don't hesitate to reach out to our support team.

Welcome aboard! 🚀
The ${APP_NAME} Team
  `;

  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Welcome to ${APP_NAME}! Your account is ready 🚀`,
      text,
      html,
    });
    
    console.log(`✅ Welcome email sent to ${email}`);
    return true;
  } catch (error) {
    console.error("❌ Failed to send welcome email:", error);
    return false;
  }
}
