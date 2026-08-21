/*
  Warnings:

  - You are about to drop the column `default_workspace_id` on the `user_preferences` table. All the data in the column will be lost.
  - You are about to drop the `account_lockouts` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `agents` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `audit_logs` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `database_connections` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `jobs` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `knowledge_bases` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `login_attempts` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `repositories` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `sources` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `token_blacklist` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `workspace_members` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `workspaces` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "database_connections" DROP CONSTRAINT "database_connections_connected_user_id_fkey";

-- DropForeignKey
ALTER TABLE "database_connections" DROP CONSTRAINT "database_connections_owner_id_fkey";

-- DropForeignKey
ALTER TABLE "knowledge_bases" DROP CONSTRAINT "knowledge_bases_workspace_id_fkey";

-- DropForeignKey
ALTER TABLE "workspace_members" DROP CONSTRAINT "workspace_members_user_id_fkey";

-- DropForeignKey
ALTER TABLE "workspace_members" DROP CONSTRAINT "workspace_members_workspace_id_fkey";

-- DropForeignKey
ALTER TABLE "workspaces" DROP CONSTRAINT "workspaces_owner_id_fkey";

-- AlterTable
ALTER TABLE "user_preferences" DROP COLUMN "default_workspace_id";

-- DropTable
DROP TABLE "account_lockouts";

-- DropTable
DROP TABLE "agents";

-- DropTable
DROP TABLE "audit_logs";

-- DropTable
DROP TABLE "database_connections";

-- DropTable
DROP TABLE "jobs";

-- DropTable
DROP TABLE "knowledge_bases";

-- DropTable
DROP TABLE "login_attempts";

-- DropTable
DROP TABLE "repositories";

-- DropTable
DROP TABLE "sources";

-- DropTable
DROP TABLE "token_blacklist";

-- DropTable
DROP TABLE "workspace_members";

-- DropTable
DROP TABLE "workspaces";

-- CreateTable
CREATE TABLE "billing_usage" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "subscription_tier" TEXT NOT NULL DEFAULT 'free',
    "repos_count" INTEGER NOT NULL DEFAULT 0,
    "docs_count" INTEGER NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "billing_usage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "chunk_snapshot" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "source_id" VARCHAR(255) NOT NULL,
    "filename" VARCHAR(255) NOT NULL,
    "start_byte" BIGINT NOT NULL,
    "end_byte" BIGINT NOT NULL,
    "chunk_key" VARCHAR(255) NOT NULL,
    "chunk_hash" VARCHAR(255) NOT NULL,
    "commit_id" VARCHAR(255),
    "embedding_model" VARCHAR(100) NOT NULL,
    "last_indexed_at" TIMESTAMPTZ(6),
    "tombstone" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "chunk_snapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "billing_usage_user_id_key" ON "billing_usage"("user_id");

-- CreateIndex
CREATE INDEX "idx_chunk_snapshot_source_file" ON "chunk_snapshot"("source_id", "filename");

-- CreateIndex
CREATE INDEX "idx_chunk_snapshot_key" ON "chunk_snapshot"("chunk_key");

-- AddForeignKey
ALTER TABLE "billing_usage" ADD CONSTRAINT "billing_usage_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
