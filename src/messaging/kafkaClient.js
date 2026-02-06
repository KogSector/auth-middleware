/**
 * Kafka Client for Auth Middleware
 * =================================
 *
 * Publishes authentication events to Kafka for audit logging
 * and inter-service communication.
 * Supports both self-hosted Kafka and Confluent Cloud.
 */

const { Kafka, Partitioners, logLevel } = require('kafkajs');
const logger = require('../utils/logger');

/**
 * Authentication event schema
 * @typedef {Object} AuthEvent
 * @property {string} eventId - Unique event identifier
 * @property {string} userId - User identifier
 * @property {string} eventType - Event type (login, logout, token_refresh, etc.)
 * @property {Object} metadata - Additional event metadata
 * @property {string} timestamp - ISO timestamp
 */

/**
 * Consistent hash partitioner for Kafka
 * Ensures events for the same user go to the same partition
 */
class ConsistentHashPartitioner {
    constructor(numPartitions) {
        this.numPartitions = numPartitions;
    }

    /**
     * Hash function using djb2 algorithm - O(n) where n = key length
     * @param {string} key - Key to hash
     * @returns {number} Hash value
     */
    hash(key) {
        let hash = 5381;
        for (let i = 0; i < key.length; i++) {
            hash = ((hash << 5) + hash) ^ key.charCodeAt(i);
        }
        return Math.abs(hash);
    }

    /**
     * Get partition for a key
     * @param {string} key - Partition key
     * @returns {number} Partition number
     */
    getPartition(key) {
        return this.hash(key) % this.numPartitions;
    }
}

/**
 * Create Kafka client configuration from environment
 * @returns {Object} KafkaJS configuration
 */
function createKafkaConfig(clientId) {
    const environment = process.env.ENVIRONMENT || 'development';

    if (environment === 'production') {
        return {
            clientId: clientId,
            brokers: [process.env.CONFLUENT_BOOTSTRAP_SERVERS],
            ssl: true,
            sasl: {
                mechanism: 'plain',
                username: process.env.CONFLUENT_API_KEY,
                password: process.env.CONFLUENT_API_SECRET,
            },
            logLevel: logLevel.WARN,
            retry: {
                retries: 3,
                initialRetryTime: 1000,
                maxRetryTime: 30000,
            },
        };
    } else {
        return {
            clientId: clientId,
            brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
            logLevel: logLevel.WARN,
            retry: {
                retries: 3,
                initialRetryTime: 1000,
                maxRetryTime: 30000,
            },
        };
    }
}

class KafkaClient {
    static TOPICS = {
        AUTH_EVENTS: 'auth.events',
        SESSION_EVENTS: 'session.events',
        AUDIT_LOG: 'audit.log',
    };

    /**
     * Create a new Kafka client
     * @param {Object} config - Configuration options
     * @param {string} config.brokers - Comma-separated broker list
     * @param {string} config.clientId - Client identifier
     * @param {number} config.numPartitions - Number of partitions for hashing
     */
    constructor(config = {}) {
        this.config = {
            clientId: config.clientId || 'auth-middleware',
            numPartitions: config.numPartitions || 3,
        };

        const kafkaConfig = createKafkaConfig(this.config.clientId);

        // Override brokers if manually specified (for testing)
        if (config.brokers) {
            kafkaConfig.brokers = config.brokers.split(',');
        }

        this.kafka = new Kafka(kafkaConfig);

        this.producer = null;
        this.consumer = null;
        this.partitioner = new ConsistentHashPartitioner(this.config.numPartitions);

        // Log connection type
        if (process.env.ENVIRONMENT === 'production') {
            logger.info('Using SASL_SSL for Confluent Cloud connection');
        }
    }

    /**
     * Initialize the Kafka producer
     */
    async initProducer() {
        if (this.producer) return;

        this.producer = this.kafka.producer({
            createPartitioner: Partitioners.DefaultPartitioner,
            idempotent: true,
            maxInFlightRequests: 5,
        });

        await this.producer.connect();
        logger.info('Kafka producer connected');
    }

    /**
     * Publish an authentication event
     * @param {AuthEvent} event - Event to publish
     */
    async publishAuthEvent(event) {
        if (!this.producer) {
            await this.initProducer();
        }

        const key = event.userId;
        const partition = this.partitioner.getPartition(key);

        try {
            await this.producer.send({
                topic: KafkaClient.TOPICS.AUTH_EVENTS,
                messages: [
                    {
                        key,
                        value: JSON.stringify(event),
                        partition,
                        headers: {
                            eventType: event.eventType,
                            timestamp: event.timestamp,
                        },
                    },
                ],
            });

            logger.debug(`Published auth event: ${event.eventType} for user ${event.userId}`);
        } catch (error) {
            logger.error(`Failed to publish auth event: ${error.message}`);
            throw error;
        }
    }

    /**
     * Publish a session event
     * @param {Object} event - Session event
     */
    async publishSessionEvent(event) {
        if (!this.producer) {
            await this.initProducer();
        }

        try {
            await this.producer.send({
                topic: KafkaClient.TOPICS.SESSION_EVENTS,
                messages: [
                    {
                        key: event.sessionId,
                        value: JSON.stringify(event),
                    },
                ],
            });
        } catch (error) {
            logger.error(`Failed to publish session event: ${error.message}`);
            throw error;
        }
    }

    /**
     * Close the Kafka client
     */
    async close() {
        if (this.producer) {
            await this.producer.disconnect();
            this.producer = null;
        }
        if (this.consumer) {
            await this.consumer.disconnect();
            this.consumer = null;
        }
        logger.info('Kafka client closed');
    }
}

module.exports = KafkaClient;
