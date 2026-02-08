/**
 * Kafka Client for Auth Middleware
 * =================================
 *
 * Wrapper around @confuse/events Producer.
 * Adapter to maintain existing API while using shared library.
 */

import {
    EventProducer,
    KafkaConfig,
    Topics,
    AuthEvent,
    SessionEvent,
    createEventHeaders,
    createEventMetadata
} from '@confuse/events';
import logger from '../utils/logger.js';

class KafkaClient {
    static TOPICS = {
        AUTH_EVENTS: Topics.AUTH_EVENTS,
        SESSION_EVENTS: Topics.SESSION_EVENTS,
        AUDIT_LOG: 'audit.log', // Not in shared topics? Keeping as is/legacy.
    };

    private producer: EventProducer;
    public isConnected: boolean;

    constructor(config = {}) {
        // We use KafkaConfig from environment variables (standardized)
        const kafkaConfig = KafkaConfig.fromEnv();
        this.producer = new EventProducer(kafkaConfig);
        this.isConnected = false;
    }

    /**
     * Initialize the Kafka producer
     */
    async initProducer() {
        if (this.isConnected) return;

        try {
            await this.producer.connect();
            this.isConnected = true;
            logger.info('Kafka producer connected (via shared library)');
        } catch (error: any) {
            logger.error(`Failed to connect Kafka producer: ${error.message}`);
            // Retry handled by library? Library uses bare kafkajs.
            // We'll throw to let caller decide.
            throw error;
        }
    }

    /**
     * Publish an authentication event
     * @param {Object} eventPayload - Event payload (partial AuthEvent)
     */
    async publishAuthEvent(eventPayload: any) {
        if (!this.isConnected) {
            await this.initProducer();
        }

        // Destructure payload to avoid overwriting typed metadata with input metadata object
        const { userId, eventType, metadata, ...rest } = eventPayload;

        const event: AuthEvent = {
            headers: createEventHeaders('auth-middleware', 'AUTH_EVENT'),
            metadata: createEventMetadata(),
            user_id: userId,
            event_type: eventType,
            ip_address: metadata?.ip,
            user_agent: metadata?.userAgent,
            success: true, // Defaulting/Adapting
            failure_reason: undefined,
            ...rest, // Overlay provided fields (excluding metadata/userId/eventType)
        };

        // Ensure headers.correlation_id is set if present in metadata
        if (eventPayload.metadata?.correlationId) {
            event.headers.correlation_id = eventPayload.metadata.correlationId;
        }

        try {
            // Publisher handles partitioning/keying if using specific methods
            // We use generic publish with topic
            // Shared library producer.publish(topic, event, key?)
            // We use user_id as key for ordering
            await this.producer.publishWithKey(event, Topics.AUTH_EVENTS, event.user_id);

            logger.debug(`Published auth event: ${event.event_type} for user ${event.user_id}`);
        } catch (error: any) {
            logger.error(`Failed to publish auth event: ${error.message}`);
            throw error;
        }
    }

    /**
     * Publish a session event
     * @param {Object} eventPayload - Session event payload
     */
    async publishSessionEvent(eventPayload: any) {
        if (!this.isConnected) {
            await this.initProducer();
        }

        const { sessionId, userId, eventType, metadata, ...rest } = eventPayload;

        const event: SessionEvent = {
            headers: createEventHeaders('auth-middleware', 'SESSION_EVENT'),
            metadata: createEventMetadata(),
            session_id: sessionId,
            user_id: userId,
            event_type: eventType,
            expires_at: 0, // Needs mapping
            ...rest
        };

        try {
            await this.producer.publishWithKey(event, Topics.SESSION_EVENTS, event.session_id);
        } catch (error: any) {
            logger.error(`Failed to publish session event: ${error.message}`);
            throw error;
        }
    }

    /**
     * Close the Kafka client
     */
    async close() {
        if (this.isConnected) {
            await this.producer.disconnect();
            this.isConnected = false;
        }
        logger.info('Kafka client closed');
    }
}

export default KafkaClient;
