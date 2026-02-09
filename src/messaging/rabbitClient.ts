/**
 * RabbitMQ Client for Auth Middleware
 * ====================================
 *
 * Provides async RabbitMQ operations for authentication
 * task queues and RPC patterns.
 */

import * as amqp from 'amqplib';
import { Connection, Channel, ConsumeMessage } from 'amqplib';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger.js';

interface RabbitConfig {
    url?: string;
    prefetchCount?: number;
}

interface PublishOptions {
    priority?: number;
    [key: string]: any;
}

interface RpcResolver {
    resolve: (value: any) => void;
}

/**
 * RabbitMQ connection and channel management
 */
export default class RabbitClient {
    static EXCHANGES = {
        AUTH: 'auth.exchange',
        NOTIFICATION: 'notification.exchange',
    };

    static QUEUES = {
        AUTH_VERIFY: 'auth.verify',
        AUTH_SESSION: 'auth.session',
        NOTIFICATION_EMAIL: 'notification.email',
    };

    private config: { url: string; prefetchCount: number };
    private connection: any = null;
    private channel: Channel | null = null;
    private replyQueue: string | null = null;
    private pendingRpcCalls: Map<string, RpcResolver> = new Map();

    /**
     * Create a new RabbitMQ client
     * @param {Object} config - Configuration options
     */
    constructor(config: RabbitConfig = {}) {
        this.config = {
            url: config.url || process.env.RABBITMQ_URL || 'amqp://confuse:confuse_dev_pass@localhost:5672',
            prefetchCount: config.prefetchCount || 10,
        };
    }

    /**
     * Connect to RabbitMQ
     */
    async connect(): Promise<void> {
        if (this.connection) return;

        try {
            this.connection = await amqp.connect(this.config.url);
            this.channel = await this.connection.createChannel();
            if (this.channel) {
                await this.channel.prefetch(this.config.prefetchCount);
            }

            // Handle connection errors
            this.connection.on('error', (err: Error) => {
                logger.error(`RabbitMQ connection error: ${err.message}`);
                this.connection = null;
                this.channel = null;
            });

            this.connection.on('close', () => {
                logger.warn('RabbitMQ connection closed');
                this.connection = null;
                this.channel = null;
            });

            logger.info('RabbitMQ client connected');
        } catch (error: any) {
            logger.error(`Failed to connect to RabbitMQ: ${error.message}`);
            throw error;
        }
    }

    /**
     * Ensure connection is active
     */
    async ensureConnected(): Promise<void> {
        if (!this.connection || !this.channel) {
            await this.connect();
        }
    }

    /**
     * Publish a message to an exchange
     * @param {string} exchange - Exchange name
     * @param {string} routingKey - Routing key
     * @param {Object} message - Message to publish
     * @param {Object} options - Publish options
     */
    async publish(exchange: string, routingKey: string, message: any, options: PublishOptions = {}): Promise<void> {
        await this.ensureConnected();

        const content = Buffer.from(JSON.stringify(message));
        const publishOptions = {
            persistent: true,
            messageId: uuidv4(),
            timestamp: Date.now(),
            contentType: 'application/json',
            priority: options.priority || 5,
            ...options,
        };

        try {
            if (this.channel) {
                this.channel.publish(exchange, routingKey, content, publishOptions);
                logger.debug(`Published to ${exchange}/${routingKey}`);
            }
        } catch (error: any) {
            logger.error(`Failed to publish message: ${error.message}`);
            throw error;
        }
    }

    /**
     * Publish an auth verification request
     * @param {Object} request - Verification request
     */
    async publishAuthVerify(request: any): Promise<void> {
        await this.publish(
            RabbitClient.EXCHANGES.AUTH,
            'verify',
            request,
            { priority: 8 } // High priority for auth
        );
    }

    /**
     * Publish a session event
     * @param {Object} event - Session event
     */
    async publishSessionEvent(event: any): Promise<void> {
        await this.publish(
            RabbitClient.EXCHANGES.AUTH,
            'session',
            event
        );
    }

    /**
     * Make an RPC call and wait for response
     * @param {string} queue - Target queue
     * @param {Object} message - Request message
     * @param {number} timeout - Timeout in milliseconds
     * @returns {Promise<Object>} Response
     */
    async rpcCall(queue: string, message: any, timeout: number = 30000): Promise<any> {
        await this.ensureConnected();

        if (!this.channel) throw new Error('Channel not initialized');

        // Create reply queue if not exists
        if (!this.replyQueue) {
            const { queue: replyTo } = await this.channel.assertQueue('', {
                exclusive: true,
                autoDelete: true,
            });
            this.replyQueue = replyTo;

            // Set up consumer for replies
            this.channel.consume(
                this.replyQueue,
                (msg: ConsumeMessage | null) => {
                    if (!msg) return;
                    const correlationId = msg.properties.correlationId;
                    const resolver = this.pendingRpcCalls.get(correlationId);
                    if (resolver) {
                        resolver.resolve(JSON.parse(msg.content.toString()));
                        this.pendingRpcCalls.delete(correlationId);
                    }
                },
                { noAck: true }
            );
        }

        return new Promise((resolve, reject) => {
            const correlationId = uuidv4();

            // Set up timeout
            const timer = setTimeout(() => {
                this.pendingRpcCalls.delete(correlationId);
                reject(new Error('RPC call timeout'));
            }, timeout);

            // Store resolver
            this.pendingRpcCalls.set(correlationId, {
                resolve: (result) => {
                    clearTimeout(timer);
                    resolve(result);
                },
            });

            // Send request
            this.channel?.sendToQueue(queue, Buffer.from(JSON.stringify(message)), {
                correlationId,
                replyTo: this.replyQueue!,
                contentType: 'application/json',
            });
        });
    }

    /**
     * Consume messages from a queue
     * @param {string} queue - Queue to consume from
     * @param {Function} handler - Message handler (async)
     */
    async consume(queue: string, handler: (content: any) => Promise<boolean>): Promise<void> {
        await this.ensureConnected();

        if (!this.channel) return;

        await this.channel.consume(
            queue,
            async (msg: ConsumeMessage | null) => {
                if (!msg) return;

                try {
                    const content = JSON.parse(msg.content.toString());
                    const result = await handler(content);

                    if (this.channel) {
                        if (result) {
                            this.channel.ack(msg);
                        } else {
                            // Requeue on failure
                            this.channel.nack(msg, false, true);
                        }
                    }
                } catch (error: any) {
                    logger.error(`Error processing message: ${error.message}`);
                    // Don't requeue on error (send to DLQ)
                    if (this.channel) {
                        this.channel.nack(msg, false, false);
                    }
                }
            },
            { noAck: false }
        );

        logger.info(`Started consuming from ${queue}`);
    }

    /**
     * Close the RabbitMQ connection
     */
    async close(): Promise<void> {
        if (this.channel) {
            await this.channel.close();
            this.channel = null;
        }
        if (this.connection) {
            await this.connection.close();
            this.connection = null;
        }
        logger.info('RabbitMQ client closed');
    }
}
