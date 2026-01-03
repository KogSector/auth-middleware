/**
 * ConFuse Messaging Module for Node.js Services
 * =============================================
 *
 * Provides Kafka and RabbitMQ integration for auth-middleware.
 */

const KafkaClient = require('./kafkaClient');
const RabbitClient = require('./rabbitClient');
const CircuitBreaker = require('./circuitBreaker');
const BloomFilter = require('./bloomFilter');

module.exports = {
    KafkaClient,
    RabbitClient,
    CircuitBreaker,
    BloomFilter,
};
