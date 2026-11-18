"use client";

import { useState } from "react";
import Link from "next/link";
import { signOut } from "next-auth/react";
import { signOut as firebaseSignOut } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { Button } from "@/components/ui/button";
import { NotificationsBell } from "@/components/app/notifications-bell";

export function AppHeader({
  name,
  role,
  homeHref,
}: {
  name: string;
  role: string;
  homeHref: string;
}) {
  const [isSigningOut, setIsSigningOut] = useState(false);

  const handleSignOut = async () => {
    setIsSigningOut(true);
    try {
      await Promise.allSettled([
        firebaseSignOut(auth).catch((err) => console.warn("[AUTH] Firebase client signOut error:", err)),
        signOut({ redirect: false }).catch((err) => console.warn("[AUTH] NextAuth signOut error:", err)),
      ]);
    } finally {
      window.location.href = "/login";
    }
  };

  return (
    <header className="border-b bg-white">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
        <div className="min-w-0">
          <Link href={homeHref} className="truncate text-sm font-semibold">
            Digital BE Project Log Book
          </Link>
          <p className="truncate text-xs text-muted-foreground">
            Anantrao Pawar College of Engineering &amp; Research
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right text-xs">
            <div className="font-medium">{name}</div>
            <div className="text-muted-foreground">{role}</div>
          </div>
          <NotificationsBell />
          <Button
            variant="outline"
            size="sm"
            disabled={isSigningOut}
            onClick={handleSignOut}
          >
            {isSigningOut ? "Signing out..." : "Sign out"}
          </Button>
        </div>
      </div>
    </header>
  );
}
