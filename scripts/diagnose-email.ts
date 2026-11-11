import dotenv from "dotenv";
dotenv.config();

import {
  emailProvider,
  getSenderAddress,
  getSmtpConfig,
  sendEmail,
  verifySmtpHealth,
} from "../apps/api/src/email/index.js";

async function diagnose() {
  console.log("══════════════════════════════════════════════════════════════════");
  console.log("       Digital BE Project Logbook — Email Diagnostics Tool       ");
  console.log("══════════════════════════════════════════════════════════════════\n");

  // Check Current Public IP
  let publicIp = "unknown";
  try {
    const res = await fetch("https://api.ipify.org?format=json");
    if (res.ok) {
      const data = (await res.json()) as { ip: string };
      publicIp = data.ip;
    }
  } catch {}
  console.log(`[0] Current Outbound Public IP: ${publicIp}`);

  const provider = emailProvider();
  console.log(`[1] Detected EMAIL_PROVIDER: "${provider}"`);

  // Check Sender
  try {
    const sender = getSenderAddress();
    console.log(`[2] Configured EMAIL_FROM: "${sender.raw}" (Email: ${sender.email})`);
  } catch (err: any) {
    console.error(`[2] EMAIL_FROM ERROR: ${err.message}`);
  }

  // Check Brevo REST API
  const brevoApiKey = (process.env.BREVO_API_KEY || process.env.BREVO_KEY || "").trim();
  if (brevoApiKey) {
    console.log(`\n[3] Checking Brevo REST API (api-key: ${brevoApiKey.slice(0, 10)}...):`);
    try {
      const res = await fetch("https://api.brevo.com/v3/account", {
        headers: { "api-key": brevoApiKey, accept: "application/json" },
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        console.log(`    >>> SUCCESS: Brevo API Key is VALID! Account: ${(data as any).email || "Active"}`);
      } else {
        console.error(`    >>> FAILED: Brevo API Key returned status ${res.status}: ${(data as any).message || ""}`);
      }
    } catch (e: any) {
      console.error(`    >>> FAILED: Network error reaching Brevo API: ${e.message}`);
    }
  } else {
    console.log("\n[3] Brevo REST API: BREVO_API_KEY is not configured.");
    const smtpPass = (process.env.BREVO_SMTP_PASSWORD || "").trim();
    if (smtpPass.startsWith("xsmtpsib-")) {
      console.log("    (Note: BREVO_SMTP_PASSWORD starts with 'xsmtpsib-', which is an SMTP relay key, not a REST API key).");
    }
  }

  // Check SMTP
  const smtpUser = process.env.BREVO_SMTP_USER || process.env.SMTP_USER || "";
  const smtpPass = process.env.BREVO_SMTP_PASSWORD || process.env.SMTP_PASSWORD || "";
  if (smtpUser && smtpPass) {
    const config = getSmtpConfig();
    console.log(`\n[4] Checking SMTP Connection to ${config.host}:${config.port} (user: ${config.user}):`);
    const health = await verifySmtpHealth();
    if (health.ok) {
      console.log("    >>> SUCCESS: SMTP connection & authentication verified!");
    } else {
      console.error(`    >>> FAILED: SMTP check failed with: ${health.error}`);
      if (health.error?.includes("525") || health.error?.includes("Unauthorized IP address")) {
        console.log("\n    [!] DIAGNOSIS: Brevo IP blocking is active for this SMTP key.");
        console.log(`        Your server/machine IP (${publicIp}) is NOT in Brevo's Authorized IPs list.`);
        console.log("\n    >>> HOW TO FIX BREVO 525 ERROR:");
        console.log("        1. Log into your Brevo account (https://app.brevo.com).");
        console.log("        2. In the top right, go to Settings -> Security -> Authorized IPs.");
        console.log("        3. In the 'Blocking unauthorized IP addresses' section, find 'API keys and SMTP keys'.");
        console.log("        4. Click 'Deactivate' (or click 'Authorize IP address' and add " + publicIp + ").");
        console.log("        5. Save and retry!");
        console.log("\n    >>> ALTERNATIVE (FOR LOCAL DEVELOPMENT):");
        console.log("        Set EMAIL_PROVIDER=\"console\" in .env to print verification links to the terminal");
        console.log("        and display a clickable 'Verify my email' link directly in the browser.");
      }
    }
  } else {
    console.log("\n[4] SMTP: SMTP credentials are not configured.");
  }

  // Optional live send test if email target supplied
  const testRecipient = process.argv[2]?.trim();
  if (testRecipient && testRecipient.includes("@")) {
    console.log(`\n[5] Attempting live test email to: ${testRecipient}...`);
    try {
      const res = await sendEmail({
        to: testRecipient,
        subject: "Digital BE Log Book — Pipeline Test Email",
        text: "This is a test email sent from the Digital BE Log Book diagnostics tool.",
        html: "<p>This is a test email sent from the <strong>Digital BE Log Book</strong> diagnostics tool.</p>",
      });
      console.log(`    >>> SUCCESS: Test email dispatched via ${res.provider}! (id: ${res.messageId || "n/a"})`);
    } catch (err: any) {
      console.error(`    >>> FAILED: Test email could not be sent: ${err.message}`);
    }
  } else if (!testRecipient) {
    console.log("\n[Tip] To test sending a live email, run:");
    console.log("      npx tsx scripts/diagnose-email.ts your-email@domain.com");
  }

  console.log("\n══════════════════════════════════════════════════════════════════\n");
}

diagnose();
