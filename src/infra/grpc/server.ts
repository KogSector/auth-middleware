/**
 * Auth Middleware gRPC Server
 * 
 * Implements the Auth gRPC service defined in proto/auth.proto
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import { logger } from './logger';

// Load proto file
const PROTO_PATH = path.join(__dirname, '..', 'proto', 'auth.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
});

// Load package
const authProto = grpc.loadPackageDefinition(packageDefinition).confuse.auth.v1 as any;

/**
 * Auth service implementation
 */
class AuthService {
    async ValidateToken(call: grpc.ServerUnaryCall<any, any>, callback: grpc.sendUnaryData<any>) {
        const { token } = call.request;
        logger.info('gRPC ValidateToken called');

        // TODO: Implement token validation logic
        callback(new Error('Not yet implemented'), null);
    }

    async GetUser(call: grpc.ServerUnaryCall<any, any>, callback: grpc.sendUnaryData<any>) {
        const { user_id } = call.request;
        logger.info('gRPC GetUser called', { user_id });

        // TODO: Implement user retrieval logic
        callback(new Error('Not yet implemented'), null);
    }
}

/**
 * Start the gRPC server
 */
export async function startGrpcServer() {
    const server = new grpc.Server();
    const service = new AuthService();

    // Add service
    server.addService(authProto.Auth.service, {
        ValidateToken: service.ValidateToken.bind(service),
        GetUser: service.GetUser.bind(service),
    });

    // Bind server
    const grpcPort = process.env.GRPC_PORT || '50058';
    server.bindAsync(
        `0.0.0.0:${grpcPort}`,
        grpc.ServerCredentials.createInsecure(),
        (err, port) => {
            if (err) {
                logger.error('Failed to start gRPC server', { error: err.message });
                throw err;
            }

            logger.info(`auth-middleware gRPC server started on port ${port}`);
            server.start();
        }
    );

    return server;
}
