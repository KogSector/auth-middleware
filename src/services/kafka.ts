/**
 * ConFuse Auth Middleware - Kafka Service
 * 
 * Singleton instance of the Kafka client wrapper
 */

import { KafkaClient } from '../messaging/index.js';
import { logger } from '../utils/logger.js';

export const kafkaClient = new KafkaClient({
    clientId: 'auth-middleware',
});

// Helper to ensure connection
export async function connectKafka() {
    try {
        await kafkaClient.initProducer();
        console.log('[KAFKA] Connected successfully');
    } catch (error) {
        console.error('[KAFKA] Failed to connect:', error);
        // Don't crash, allow fallback/retry
    }
}

export async function disconnectKafka() {
    await kafkaClient.close();
}
