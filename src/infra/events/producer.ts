/**
 * Kafka Event Producer for Auth Middleware
 */
import { EventProducer, KafkaConfig } from 'confuse-common';
import { config } from '../../config.js';
import { logger } from '../../utils/logger.js';

let producer: EventProducer | null = null;

/**
 * Initialize the global Kafka event producer
 */
export async function initEventProducer(): Promise<EventProducer | null> {
    try {
        const kafkaConfig = KafkaConfig.fromEnv();
        // If a clientId override is provided, create an override config
        const producerConfig = config.kafka?.clientId
            ? Object.assign({}, kafkaConfig, { clientId: config.kafka.clientId }) as unknown as KafkaConfig
            : kafkaConfig;

        producer = new EventProducer(producerConfig);
        await producer.connect();
        
        logger.info('[AUTH-EVENTS] Kafka event producer initialized', {
            bootstrapServers: producerConfig.bootstrapServers,
            clientId: producerConfig.clientId
        });
        
        return producer;
    } catch (error) {
        logger.error('[AUTH-EVENTS] Failed to initialize Kafka event producer', { error });
        return null;
    }
}

/**
 * Get the initialized Kafka event producer
 */
export function getEventProducer(): EventProducer | null {
    return producer;
}

/**
 * Close the Kafka event producer
 */
export async function closeEventProducer(): Promise<void> {
    if (producer) {
        logger.info('[AUTH-EVENTS] Closing Kafka event producer');
        await producer.disconnect();
        producer = null;
    }
}
