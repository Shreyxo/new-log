"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { signIn, signOut, getSession } from "next-auth/react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import Link from "next/link";
import { signInWithEmailAndPassword, sendEmailVerification } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordInput } from "@/components/auth/password-input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { loginSchema } from "@/lib/validation/auth";
import { resendVerificationAction } from "@/lib/actions/auth";
import { homeForRole } from "@/lib/roles";

type LoginValues = z.infer<typeof loginSchema>;

export function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [formError, setFormError] = useState<string | null>(null);
  const [isUnverified, setIsUnverified] = useState(false);
  const [unverifiedEmail, setUnverifiedEmail] = useState("");
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const [resendDevUrl, setResendDevUrl] = useState<string | null>(null);
  const [isResending, setIsResending] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  const {
    register,
    handleSubmit,
    getValues,
    formState: { errors, isSubmitting },
  } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  async function handleResendVerification() {
    const email = unverifiedEmail || getValues("email");
    if (!email) return;

    setIsResending(true);
    setResendStatus(null);
    setResendDevUrl(null);

    try {
      if (auth.currentUser && auth.currentUser.email === email) {
        await sendEmailVerification(auth.currentUser);
        setResendStatus("Verification email sent! Check your inbox.");
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
      console.warn("Client sendEmailVerification failed, falling back to server action:", fbResendErr);
    }

    const result = await resendVerificationAction({ email });
    setIsResending(false);

    if (result.success) {
      if (result.data.alreadyVerified) {
        setResendStatus("Your email is already verified. You can sign in.");
        setIsUnverified(false);
      } else {
        setResendStatus("Verification email sent! Check your inbox.");
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

  async function onSubmit(values: LoginValues) {
    setFormError(null);
    setIsUnverified(false);
    setResendStatus(null);
    setResendDevUrl(null);

    // Step 1: Attempt Firebase Authentication client sign-in (Section 8)
    let idToken: string | null = null;
    try {
      const userCredential = await signInWithEmailAndPassword(auth, values.email, values.password);
      idToken = await userCredential.user.getIdToken();
    } catch (firebaseErr: any) {
      // If user does not exist in Firebase yet (legacy user awaiting migration),
      // we proceed to attempt migration via NextAuth Credentials Provider.
      console.info("[AUTH] Firebase client sign-in deferred/failed:", firebaseErr?.code || firebaseErr?.message);
    }

    // Step 2: NextAuth credentials sign-in
    // If idToken is present, NextAuth verifies the Firebase token.
    // If idToken is null, NextAuth checks legacy password and migrates user to Firebase.
    const result = await signIn("credentials", {
      ...(idToken ? { idToken } : { email: values.email, password: values.password }),
      redirect: false,
    });

    if (!result || result.error) {
      if (result?.error === "EMAIL_NOT_VERIFIED") {
        setIsUnverified(true);
        setUnverifiedEmail(values.email);
        setFormError("Please verify your email address before signing in.");
        return;
      }
      if (result?.error === "ACCOUNT_INACTIVE") {
        setFormError("This account has been deactivated. Please contact your HOD.");
        return;
      }
      if (result?.error === "RATE_LIMITED") {
        setFormError("Too many sign in attempts. Please wait a few minutes and try again.");
        return;
      }
      setFormError("Could not sign you in. Check your email and password.");
      return;
    }

    // Step 3 (FIX 2): Synchronize Firebase Client Session After Legacy Migration
    // If idToken was null, the user was migrated on the backend during Step 2.
    // We must sign in to the Firebase Client SDK now so the browser session is synchronized.
    if (!idToken) {
      try {
        await signInWithEmailAndPassword(auth, values.email, values.password);
      } catch (fbSyncErr: any) {
        console.error("[AUTH] Failed to synchronize Firebase client session after migration:", fbSyncErr?.code || fbSyncErr?.message);
        // Tear down NextAuth session to prevent inconsistent partial authentication
        await signOut({ redirect: false });
        setFormError("Account was migrated to Firebase, but browser session synchronization failed. Please try signing in again.");
        return;
      }
    }

    const session = await getSession();
    const next = searchParams.get("next");
    const destination = next || homeForRole(session?.user?.role);
    router.push(destination);
    router.refresh();
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      {formError ? (
        <Alert variant={isUnverified ? "default" : "destructive"}>
          <AlertDescription>
            <div className="space-y-2">
              <p>{formError}</p>
              {isUnverified ? (
                <div className="pt-1">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleResendVerification}
                    disabled={isResending || cooldown > 0}
                    className="text-xs"
                  >
                    {isResending
                      ? "Sending…"
                      : cooldown > 0
                        ? `Resend available in ${cooldown}s`
                        : "Resend verification email"}
                  </Button>
                </div>
              ) : null}
            </div>
          </AlertDescription>
        </Alert>
      ) : null}

      {resendStatus ? (
        <Alert>
          <AlertDescription>{resendStatus}</AlertDescription>
        </Alert>
      ) : null}

      {resendDevUrl ? (
        <Alert>
          <AlertDescription>
            <span className="font-medium">Dev link:</span>{" "}
            <Link className="underline" href={resendDevUrl}>
              Click to verify email
            </Link>
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-1">
        <Label htmlFor="email">College email</Label>
        <Input id="email" type="email" autoComplete="email" {...register("email")} />
        {errors.email ? <p className="text-xs text-destructive">{errors.email.message}</p> : null}
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <Label htmlFor="password">Password</Label>
          <Link
            href="/forgot-password"
            className="text-xs text-muted-foreground hover:underline"
          >
            Forgot password?
          </Link>
        </div>
        <PasswordInput
          id="password"
          autoComplete="current-password"
          {...register("password")}
        />
        {errors.password ? (
          <p className="text-xs text-destructive">{errors.password.message}</p>
        ) : null}
      </div>

      <Button type="submit" className="w-full" disabled={isSubmitting}>
        {isSubmitting ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}
