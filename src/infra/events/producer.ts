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
        producer = new EventProducer(kafkaConfig);
        await producer.connect();
        
        logger.info('[AUTH-EVENTS] Kafka event producer initialized', {
            bootstrapServers: kafkaConfig.bootstrapServers,
            clientId: kafkaConfig.clientId
        });
        
        return producer;
    } catch (error) {
        console.log('[AUTH-EVENTS] Catch block reached');
        console.log('[AUTH-EVENTS] Error:', JSON.stringify(error, Object.getOwnPropertyNames(error)));
        logger.error('[AUTH-EVENTS] Failed to initialize Kafka event producer');
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

/**
 * Publish an event with retries and optional DLQ fallback.
 * - Tries up to `retries` times with exponential backoff.
 * - On final failure publishes a simple failure envelope to configured DLQ topic.
 */
export async function publishEvent<T extends object>(
    topic: string,
    event: T,
    key?: string,
    retries = 3
): Promise<void> {
    const p = getEventProducer() || await initEventProducer();
    if (!p) {
        const err = new Error('Kafka producer not initialized');
        logger.error('[AUTH-EVENTS] publishEvent aborted', { topic, error: err.message });
        throw err;
    }

    let attempt = 0;
    let lastErr: unknown = null;

    while (attempt < retries) {
        try {
            if (typeof (p as any).publishWithKey === 'function' && key) {
                await (p as any).publishWithKey(event, topic, key);
            } else if (typeof (p as any).publish === 'function') {
                await (p as any).publish(event, topic);
            } else {
                throw new Error('Producer does not support publish API');
            }

            logger.info('[AUTH-EVENTS] Event published', { topic, attempt });
            return;
        } catch (err) {
            lastErr = err;
            const delay = Math.pow(2, attempt) * 500; // 500ms, 1s, 2s
            logger.warn('[AUTH-EVENTS] Publish attempt failed', { topic, attempt, error: err });
            // eslint-disable-next-line no-await-in-loop
            await new Promise(resolve => setTimeout(resolve, delay));
            attempt += 1;
        }
    }

    logger.error('[AUTH-EVENTS] Publish failed after retries', { topic, error: lastErr });

    // Publish failure envelope to DLQ if configured
    const dlq = config.kafka?.dlqTopic || (config.kafka?.eventsTopic ? `${config.kafka.eventsTopic}.dlq` : undefined);
    if (dlq) {
        try {
            const failureEnvelope = {
                failedTopic: topic,
                failedAt: Date.now(),
                error: String(lastErr),
                event,
            };
            if (typeof (p as any).publish === 'function') {
                await (p as any).publish(failureEnvelope, dlq);
                logger.info('[AUTH-EVENTS] Published failure envelope to DLQ', { dlq });
            }
        } catch (dlqErr) {
            logger.error('[AUTH-EVENTS] Failed to publish to DLQ', { dlq, error: dlqErr });
        }
    }

    // Surface original error to caller
    throw lastErr;
}
