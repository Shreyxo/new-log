"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { applyActionCode, sendEmailVerification } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { resendVerificationAction, syncEmailVerificationAction } from "@/lib/actions/auth";

type Props = {
  verifiedEmail: string | null;
  alreadyVerified?: boolean;
  errorMessage: string | null;
  errorCode?: string | null;
  oobCode?: string;
  mode?: string;
};

export function VerifyEmailView({
  verifiedEmail: initialVerifiedEmail,
  alreadyVerified: initialAlreadyVerified,
  errorMessage: initialErrorMessage,
  errorCode: initialErrorCode,
  oobCode,
  mode,
}: Props) {
  const [verifiedEmail, setVerifiedEmail] = useState<string | null>(initialVerifiedEmail);
  const [alreadyVerified, setAlreadyVerified] = useState(Boolean(initialAlreadyVerified));
  const [errorMessage, setErrorMessage] = useState<string | null>(initialErrorMessage);
  const [errorCode, setErrorCode] = useState<string | null>(initialErrorCode ?? null);

  const [resendEmail, setResendEmail] = useState("");
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const [resendDevUrl, setResendDevUrl] = useState<string | null>(null);
  const [isResending, setIsResending] = useState(false);
  const [isChecking, setIsChecking] = useState(false);
  const [checkStatus, setCheckStatus] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);

  // If redirected with Firebase oobCode for verifyEmail
  useEffect(() => {
    if (oobCode && (mode === "verifyEmail" || !mode)) {
      applyActionCode(auth, oobCode)
        .then(async () => {
          let userEmail = "";
          if (auth.currentUser) {
            await auth.currentUser.reload();
            userEmail = auth.currentUser.email || "";
            try {
              const idToken = await auth.currentUser.getIdToken(true);
              await syncEmailVerificationAction(idToken);
            } catch (syncErr) {
              console.warn("[AUTH] Failed to sync email verification to backend:", syncErr);
            }
          }
          setVerifiedEmail(userEmail || "your email");
          setErrorMessage(null);
        })
        .catch((err: any) => {
          console.error("[AUTH] applyActionCode failed:", err);
          setErrorCode("INVALID_TOKEN");
          setErrorMessage(
            err?.code === "auth/invalid-action-code"
              ? "This verification link is invalid or has already been used."
              : err?.message || "Failed to verify email link.",
          );
        });
    }
  }, [oobCode, mode]);

  async function handleCheckStatus() {
    setIsChecking(true);
    setCheckStatus(null);
    try {
      if (auth.currentUser) {
        await auth.currentUser.reload();
        if (auth.currentUser.emailVerified) {
          const idToken = await auth.currentUser.getIdToken(true);
          const syncRes = await syncEmailVerificationAction(idToken);
          if (syncRes.success) {
            setVerifiedEmail(auth.currentUser.email);
            setAlreadyVerified(Boolean(syncRes.data.alreadyVerified));
            setIsChecking(false);
            return;
          }
        }
      }
      setCheckStatus("Your email is not verified yet. Please click the link sent to your inbox.");
    } catch (err: any) {
      setCheckStatus(err?.message || "Could not check verification status.");
    } finally {
      setIsChecking(false);
    }
  }

  async function handleResend(e: React.FormEvent) {
    e.preventDefault();
    const targetEmail = resendEmail.trim() || auth.currentUser?.email || "";
    if (!targetEmail) return;

    setIsResending(true);
    setResendStatus(null);
    setResendDevUrl(null);

    // 1. Try Firebase client sendEmailVerification if user is authenticated in browser
    try {
      if (auth.currentUser && auth.currentUser.email === targetEmail) {
        await sendEmailVerification(auth.currentUser);
        setResendStatus("A new verification link has been sent. Please check your inbox.");
        setCooldown(60);
        const timer = setInterval(() => {
          setCooldown((prev) => {
            if (prev <= 1) {
              clearInterval(timer);
              return 0;
            }
            return prev - 1;
          });
        }, 1000);
        setIsResending(false);
        return;
      }
    } catch (fbResendErr) {
      console.warn("[AUTH] Client sendEmailVerification failed, falling back to server action:", fbResendErr);
    }

    // 2. Fallback to server action
    const result = await resendVerificationAction({ email: targetEmail });
    setIsResending(false);

    if (result.success) {
      if (result.data.alreadyVerified) {
        setResendStatus("This email is already verified. You can sign in right away.");
      } else {
        setResendStatus("A new verification link has been sent. Please check your inbox.");
        if (result.data.verificationUrl) {
          setResendDevUrl(result.data.verificationUrl);
        }
        setCooldown(60);
        const timer = setInterval(() => {
          setCooldown((prev) => {
            if (prev <= 1) {
              clearInterval(timer);
              return 0;
            }
            return prev - 1;
          });
        }, 1000);
      }
    } else {
      setResendStatus(result.error);
    }
  }

  // 1. Successfully verified
  if (verifiedEmail) {
    return (
      <div className="space-y-4">
        <Alert>
          <AlertDescription>
            {alreadyVerified ? (
              <span>
                Your email <span className="font-semibold">{verifiedEmail}</span> is already verified. You can sign in.
              </span>
            ) : (
              <span>
                Your email <span className="font-semibold">{verifiedEmail}</span> has been successfully verified! You can now sign in to access your Project Logbook.
              </span>
            )}
          </AlertDescription>
        </Alert>
        <Button asChild className="w-full">
          <Link href="/login">Go to sign in</Link>
        </Button>
      </div>
    );
  }

  // 2. Failed / Expired / Pending verification
  const isExpired = errorCode === "EXPIRED_TOKEN" || errorMessage?.toLowerCase().includes("expired");

  return (
    <div className="space-y-4">
      {errorMessage ? (
        <Alert variant="destructive">
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      ) : (
        <Alert>
          <AlertDescription>
            Please check your email and click the verification link to activate your account.
          </AlertDescription>
        </Alert>
      )}

      <div className="space-y-2">
        <Button
          type="button"
          onClick={handleCheckStatus}
          disabled={isChecking}
          className="w-full"
        >
          {isChecking ? "Checking status…" : "I have clicked the link in my email"}
        </Button>
        {checkStatus ? (
          <p className="text-xs text-center text-muted-foreground">{checkStatus}</p>
        ) : null}
      </div>

      <div className="rounded border p-4 bg-muted/30 space-y-3">
        <h3 className="text-sm font-medium">Request a new verification link</h3>
        <p className="text-xs text-muted-foreground">
          {isExpired
            ? "Your verification link has expired. Enter your email to receive a fresh link."
            : "Enter your registered college email address to receive a new verification link."}
        </p>

        <form onSubmit={handleResend} className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="resend-email" className="text-xs">
              College email
            </Label>
            <Input
              id="resend-email"
              type="email"
              placeholder="e.g. student@apcoer.edu.in"
              value={resendEmail}
              onChange={(e) => setResendEmail(e.target.value)}
              required
            />
          </div>

          <Button
            type="submit"
            variant="outline"
            size="sm"
            disabled={isResending || cooldown > 0 || !resendEmail.trim()}
            className="w-full"
          >
            {isResending
              ? "Sending…"
              : cooldown > 0
                ? `Resend available in ${cooldown}s`
                : "Resend verification email"}
          </Button>
        </form>

        {resendStatus ? (
          <Alert className="mt-2">
            <AlertDescription className="text-xs">{resendStatus}</AlertDescription>
          </Alert>
        ) : null}

        {resendDevUrl ? (
          <Alert className="mt-2">
            <AlertDescription className="text-xs">
              <span className="font-medium">Dev link:</span>{" "}
              <Link className="underline" href={resendDevUrl}>
                Verify my email
              </Link>
            </AlertDescription>
          </Alert>
        ) : null}
      </div>

      <Button asChild variant="outline" className="w-full">
        <Link href="/login">Back to sign in</Link>
      </Button>
    </div>
  );
}
