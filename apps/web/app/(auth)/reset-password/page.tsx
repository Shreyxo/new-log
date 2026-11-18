import Link from "next/link";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { ResetPasswordForm } from "@/components/auth/reset-password-form";

export const metadata = { title: "Reset password — Digital BE Log Book" };

export default function ResetPasswordPage({
  searchParams,
}: {
  searchParams?: { token?: string; oobCode?: string; mode?: string };
}) {
  const token = searchParams?.token;
  const oobCode = searchParams?.oobCode;
  const hasCode = Boolean(token || oobCode);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Reset password</CardTitle>
        <CardDescription>Choose a new password for your account.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {hasCode ? (
          <ResetPasswordForm token={token} oobCode={oobCode} />
        ) : (
          <>
            <Alert variant="destructive">
              <AlertDescription>This reset link is missing its reset code or token.</AlertDescription>
            </Alert>
            <Button asChild variant="outline" className="w-full">
              <Link href="/forgot-password">Request a new link</Link>
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}
