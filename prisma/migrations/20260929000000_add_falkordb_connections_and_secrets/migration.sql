-- Customer-owned FalkorDB connections (Cloud / self-hosted / BYOC)
-- Stores connection metadata + secret REFERENCES only. Secrets themselves
-- are AES-256-GCM encrypted in the `secrets` table.

-- CreateTable
CREATE TABLE "falkordb_connections" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "customer_id" UUID NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "host" VARCHAR(255) NOT NULL,
    "port" INTEGER NOT NULL,
    "username" VARCHAR(255),
    "password_secret_ref" VARCHAR(500),
    "graph_name" VARCHAR(255) NOT NULL,
    "tls_enabled" BOOLEAN NOT NULL DEFAULT false,
    "ca_certificate_secret_ref" VARCHAR(500),
    "client_certificate_secret_ref" VARCHAR(500),
    "client_key_secret_ref" VARCHAR(500),
    "topology" VARCHAR(20),
    "deployment_type" VARCHAR(20),
    "sentinel_master_name" VARCHAR(255),
    "status" VARCHAR(20) NOT NULL DEFAULT 'active',
    "last_tested_at" TIMESTAMP(3),
    "last_test_status" VARCHAR(20),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "falkordb_connections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "secrets" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "secret_ref" VARCHAR(500) NOT NULL,
    "owner_id" UUID NOT NULL,
    "purpose" VARCHAR(50) NOT NULL DEFAULT 'falkordb',
    "algorithm" VARCHAR(30) NOT NULL DEFAULT 'aes-256-gcm',
    "key_version" INTEGER NOT NULL DEFAULT 1,
    "ciphertext" TEXT NOT NULL,
    "iv" TEXT NOT NULL,
    "auth_tag" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "secrets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "secrets_secret_ref_key" ON "secrets"("secret_ref");

-- CreateIndex
CREATE INDEX "secrets_owner_id_idx" ON "secrets"("owner_id");

-- CreateIndex
CREATE INDEX "falkordb_connections_customer_id_idx" ON "falkordb_connections"("customer_id");

-- AddForeignKey
ALTER TABLE "falkordb_connections" ADD CONSTRAINT "falkordb_connections_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
