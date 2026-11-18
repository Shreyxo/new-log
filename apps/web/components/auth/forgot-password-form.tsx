"use client";

import { useState } from "react";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { sendPasswordResetEmail } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { requestPasswordResetAction } from "@/lib/actions/auth";
import { forgotPasswordSchema } from "@/lib/validation/auth";

type Values = z.infer<typeof forgotPasswordSchema>;

export function ForgotPasswordForm() {
  const [sent, setSent] = useState<{ resetUrl?: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Values>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: "" },
  });

  async function onSubmit(values: Values) {
    setFormError(null);

    // 1. Try Firebase password reset email first (Section 10)
    let firebaseSent = false;
    try {
      await sendPasswordResetEmail(auth, values.email);
      firebaseSent = true;
    } catch (fbErr: any) {
      console.info("[AUTH] Firebase sendPasswordResetEmail status:", fbErr?.code || fbErr?.message);
    }

    // 2. If Firebase did not send (e.g. unmigrated legacy user), fallback to legacy requestPasswordResetAction
    if (!firebaseSent) {
      try {
        const result = await requestPasswordResetAction(values);
        if (result.success && result.data.resetUrl) {
          setSent(result.data);
          return;
        }
      } catch (legacyErr) {
        console.warn("[AUTH] Legacy password reset fallback:", legacyErr);
      }
    }

    // Generic response to prevent email enumeration
    setSent({});
  }

  if (sent) {
    return (
      <div className="space-y-4">
        <Alert>
          <AlertDescription>
            If an account exists with this email address, a password reset link has been sent. This link expires in 30 minutes.
          </AlertDescription>
        </Alert>
        {sent.resetUrl ? (
          <Alert>
            <AlertDescription>
              <span className="font-medium">Development mode:</span>{" "}
              <Link className="underline" href={sent.resetUrl}>
                Reset my password
              </Link>
            </AlertDescription>
          </Alert>
        ) : null}
        <Button asChild variant="outline" className="w-full">
          <Link href="/login">Back to sign in</Link>
        </Button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      {formError ? (
        <Alert variant="destructive">
          <AlertDescription>{formError}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-1">
        <Label htmlFor="email">College email</Label>
        <Input
          id="email"
          type="email"
          autoComplete="email"
          placeholder="e.g. student@apcoer.edu.in"
          {...register("email")}
        />
        {errors.email ? <p className="text-xs text-destructive">{errors.email.message}</p> : null}
      </div>

      <Button type="submit" className="w-full" disabled={isSubmitting}>
        {isSubmitting ? "Sending reset link…" : "Send password reset link"}
      </Button>
    </form>
  );
}
