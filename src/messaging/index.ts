/**
 * ConFuse Messaging Module
 * ========================
 *
 * Provides Kafka and RabbitMQ integration.
 */

// Kafka Client replaced with shared library wrapper (TypeScript)
export { default as KafkaClient } from './kafkaClient';

// Legacy JS modules (CommonJS interop)
// Using require for JS modules to ensure correct typing/loading if allowJs is questionable
// But standard import should work with esModuleInterop
import RabbitClient from './rabbitClient.js';
import CircuitBreaker from './circuitBreaker.js';
import BloomFilter from './bloomFilter.js';

export { RabbitClient, CircuitBreaker, BloomFilter };
