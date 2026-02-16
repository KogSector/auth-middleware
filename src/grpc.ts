
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from './config.js';
import { verifyAuth0Token, extractRoles } from './services/auth0.js';
import { findById } from './services/user.js';
import { logger } from './utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PROTO_PATH = path.join(__dirname, '../proto/auth.proto');

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
});

const authProto = grpc.loadPackageDefinition(packageDefinition) as any;

/**
 * Validate Token Implementation
 */
const validateToken = async (call: any, callback: any) => {
    const { token } = call.request;

    if (!token) {
        return callback(null, { valid: false, error: 'Token is missing' });
    }

    try {
        const payload = await verifyAuth0Token(token);
        const roles = extractRoles(payload);

        callback(null, {
            valid: true,
            user_id: payload.sub,
            roles: roles,
        });
    } catch (error: any) {
        logger.warn(`[gRPC] Token validation failed: ${error.message}`);
        callback(null, { valid: false, error: error.message });
    }
};

/**
 * Get User Implementation
 */
const getUser = async (call: any, callback: any) => {
    const { user_id } = call.request;

    if (!user_id) {
        return callback({
            code: grpc.status.INVALID_ARGUMENT,
            details: 'User ID is required',
        });
    }

    try {
        const user = await findById(user_id);

        if (!user) {
            return callback({
                code: grpc.status.NOT_FOUND,
                details: 'User not found',
            });
        }

        callback(null, {
            user_id: user.id,
            email: user.email,
            roles: user.roles,
            metadata: {}, // Populate if needed
        });
    } catch (error: any) {
        logger.error(`[gRPC] GetUser failed: ${error.message}`);
        callback({
            code: grpc.status.INTERNAL,
            details: 'Internal server error',
        });
    }
};

/**
 * Start gRPC Server
 */
export const startGrpcServer = () => {
    const server = new grpc.Server();

    server.addService(authProto.confuse.auth.v1.Auth.service, {
        ValidateToken: validateToken,
        GetUser: getUser,
    });

    const bindAddr = `0.0.0.0:${config.grpcPort}`;

    server.bindAsync(bindAddr, grpc.ServerCredentials.createInsecure(), (err, port) => {
        if (err) {
            logger.error(`[gRPC] Failed to bind: ${err.message}`);
            return;
        }

        logger.info(`[gRPC] Server running on port ${port}`);
    });
};
