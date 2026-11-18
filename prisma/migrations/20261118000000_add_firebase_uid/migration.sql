-- AlterTable: Safely add firebaseUid to User without breaking existing data
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "firebaseUid" TEXT;

-- CreateIndex: Add unique index on firebaseUid for User
CREATE UNIQUE INDEX IF NOT EXISTS "User_firebaseUid_key" ON "User"("firebaseUid");
