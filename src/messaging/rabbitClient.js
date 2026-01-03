/**
 * RabbitMQ Client for Auth Middleware
 * ====================================
 *
 * Provides async RabbitMQ operations for authentication
 * task queues and RPC patterns.
 */

const amqp = require('amqplib');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

/**
 * RabbitMQ connection and channel management
 */
class RabbitClient {
    static EXCHANGES = {
        AUTH: 'auth.exchange',
        NOTIFICATION: 'notification.exchange',
    };

    static QUEUES = {
        AUTH_VERIFY: 'auth.verify',
        AUTH_SESSION: 'auth.session',
        NOTIFICATION_EMAIL: 'notification.email',
    };

    /**
     * Create a new RabbitMQ client
     * @param {Object} config - Configuration options
     */
    constructor(config = {}) {
        this.config = {
            url: config.url || process.env.RABBITMQ_URL || 'amqp://confuse:confuse_dev_pass@localhost:5672',
            prefetchCount: config.prefetchCount || 10,
        };

        this.connection = null;
        this.channel = null;
        this.replyQueue = null;
        this.pendingRpcCalls = new Map(); // For RPC pattern
    }

    /**
     * Connect to RabbitMQ
     */
    async connect() {
        if (this.connection) return;

        try {
            this.connection = await amqp.connect(this.config.url);
            this.channel = await this.connection.createChannel();
            await this.channel.prefetch(this.config.prefetchCount);

            // Handle connection errors
            this.connection.on('error', (err) => {
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
        } catch (error) {
            logger.error(`Failed to connect to RabbitMQ: ${error.message}`);
            throw error;
        }
    }

    /**
     * Ensure connection is active
     */
    async ensureConnected() {
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
    async publish(exchange, routingKey, message, options = {}) {
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
            this.channel.publish(exchange, routingKey, content, publishOptions);
            logger.debug(`Published to ${exchange}/${routingKey}`);
        } catch (error) {
            logger.error(`Failed to publish message: ${error.message}`);
            throw error;
        }
    }

    /**
     * Publish an auth verification request
     * @param {Object} request - Verification request
     */
    async publishAuthVerify(request) {
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
    async publishSessionEvent(event) {
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
    async rpcCall(queue, message, timeout = 30000) {
        await this.ensureConnected();

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
                (msg) => {
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
            this.channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), {
                correlationId,
                replyTo: this.replyQueue,
                contentType: 'application/json',
            });
        });
    }

    /**
     * Consume messages from a queue
     * @param {string} queue - Queue to consume from
     * @param {Function} handler - Message handler (async)
     */
    async consume(queue, handler) {
        await this.ensureConnected();

        await this.channel.consume(
            queue,
            async (msg) => {
                if (!msg) return;

                try {
                    const content = JSON.parse(msg.content.toString());
                    const result = await handler(content);

                    if (result) {
                        this.channel.ack(msg);
                    } else {
                        // Requeue on failure
                        this.channel.nack(msg, false, true);
                    }
                } catch (error) {
                    logger.error(`Error processing message: ${error.message}`);
                    // Don't requeue on error (send to DLQ)
                    this.channel.nack(msg, false, false);
                }
            },
            { noAck: false }
        );

        logger.info(`Started consuming from ${queue}`);
    }

    /**
     * Close the RabbitMQ connection
     */
    async close() {
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

module.exports = RabbitClient;
