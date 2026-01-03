/**
 * Circuit Breaker Pattern - DSA/Design Pattern Implementation
 * ============================================================
 *
 * Prevents cascading failures by stopping requests to failing services.
 * Uses exponential backoff with jitter for recovery attempts.
 */

const logger = require('../utils/logger');

/**
 * Circuit states
 */
const CircuitState = {
    CLOSED: 'closed',      // Normal operation
    OPEN: 'open',          // Blocking requests
    HALF_OPEN: 'half_open', // Testing recovery
};

/**
 * Circuit breaker with exponential backoff and jitter
 */
class CircuitBreaker {
    /**
     * Create a circuit breaker
     * @param {Object} options - Configuration options
     */
    constructor(options = {}) {
        this.failureThreshold = options.failureThreshold || 5;
        this.recoveryTimeout = options.recoveryTimeout || 30000; // ms
        this.halfOpenMaxCalls = options.halfOpenMaxCalls || 3;
        this.maxBackoff = options.maxBackoff || 300000; // 5 minutes
        this.exponentialBackoff = options.exponentialBackoff !== false;

        this.state = CircuitState.CLOSED;
        this.failures = 0;
        this.successes = 0;
        this.consecutiveSuccesses = 0;
        this.halfOpenCalls = 0;
        this.retryCount = 0;
        this.lastFailureTime = null;
        this.nextRetryTime = null;

        // Sliding window for failures (O(1) add/remove)
        this.failureWindow = options.failureWindow || 60000; // 1 minute
        this.failureTimes = [];
    }

    /**
     * Count recent failures within the sliding window
     * Time complexity: O(n) worst case, but amortized O(1) with cleanup
     * @returns {number} Number of recent failures
     */
    countRecentFailures() {
        const now = Date.now();
        const cutoff = now - this.failureWindow;

        // Remove old failures (amortized O(1))
        while (this.failureTimes.length > 0 && this.failureTimes[0] < cutoff) {
            this.failureTimes.shift();
        }

        return this.failureTimes.length;
    }

    /**
     * Calculate backoff with exponential increase and jitter
     * @returns {number} Backoff time in milliseconds
     */
    calculateBackoff() {
        if (!this.exponentialBackoff) {
            return this.recoveryTimeout;
        }

        // Exponential: base * 2^retry
        const baseDelay = this.recoveryTimeout * Math.pow(2, this.retryCount);
        const cappedDelay = Math.min(baseDelay, this.maxBackoff);

        // Jitter: 50-100% of delay to prevent thundering herd
        const jitter = 0.5 + Math.random() * 0.5;
        return Math.floor(cappedDelay * jitter);
    }

    /**
     * Transition to a new state
     * @param {string} newState - New circuit state
     */
    transitionTo(newState) {
        const oldState = this.state;
        this.state = newState;

        switch (newState) {
            case CircuitState.OPEN:
                const backoff = this.calculateBackoff();
                this.nextRetryTime = Date.now() + backoff;
                this.retryCount++;
                logger.warn(
                    `Circuit OPENED after ${this.failures} failures. Retry in ${backoff}ms`
                );
                break;

            case CircuitState.HALF_OPEN:
                this.halfOpenCalls = 0;
                logger.info('Circuit HALF-OPEN, testing recovery');
                break;

            case CircuitState.CLOSED:
                this.retryCount = 0;
                this.failures = 0;
                this.failureTimes = [];
                this.consecutiveSuccesses = 0;
                logger.info('Circuit CLOSED, normal operation resumed');
                break;
        }
    }

    /**
     * Check if request should be allowed
     * @returns {boolean} True if request is allowed
     */
    allowRequest() {
        switch (this.state) {
            case CircuitState.CLOSED:
                return true;

            case CircuitState.OPEN:
                if (this.nextRetryTime && Date.now() >= this.nextRetryTime) {
                    this.transitionTo(CircuitState.HALF_OPEN);
                    return true;
                }
                return false;

            case CircuitState.HALF_OPEN:
                return this.halfOpenCalls < this.halfOpenMaxCalls;
        }
    }

    /**
     * Record a successful call
     */
    recordSuccess() {
        this.successes++;
        this.consecutiveSuccesses++;

        if (this.state === CircuitState.HALF_OPEN) {
            this.halfOpenCalls++;
            if (this.halfOpenCalls >= this.halfOpenMaxCalls) {
                this.transitionTo(CircuitState.CLOSED);
            }
        }
    }

    /**
     * Record a failed call
     */
    recordFailure() {
        const now = Date.now();
        this.failures++;
        this.consecutiveSuccesses = 0;
        this.lastFailureTime = now;
        this.failureTimes.push(now);

        if (this.state === CircuitState.HALF_OPEN) {
            // Single failure in half-open triggers open
            this.transitionTo(CircuitState.OPEN);
        } else if (this.state === CircuitState.CLOSED) {
            const recentFailures = this.countRecentFailures();
            if (recentFailures >= this.failureThreshold) {
                this.transitionTo(CircuitState.OPEN);
            }
        }
    }

    /**
     * Execute a function with circuit breaker protection
     * @param {Function} fn - Async function to execute
     * @returns {Promise<any>} Result of the function
     * @throws {Error} If circuit is open or function fails
     */
    async execute(fn) {
        if (!this.allowRequest()) {
            const waitTime = this.nextRetryTime - Date.now();
            throw new CircuitOpenError(
                `Circuit is OPEN. Retry in ${Math.ceil(waitTime / 1000)}s`
            );
        }

        try {
            const result = await fn();
            this.recordSuccess();
            return result;
        } catch (error) {
            this.recordFailure();
            throw error;
        }
    }

    /**
     * Wrap a function with circuit breaker protection
     * @param {Function} fn - Function to wrap
     * @returns {Function} Wrapped function
     */
    wrap(fn) {
        return (...args) => this.execute(() => fn(...args));
    }

    /**
     * Get current statistics
     * @returns {Object} Circuit breaker stats
     */
    getStats() {
        return {
            state: this.state,
            failures: this.failures,
            successes: this.successes,
            consecutiveSuccesses: this.consecutiveSuccesses,
            retryCount: this.retryCount,
            lastFailureTime: this.lastFailureTime,
            nextRetryTime: this.nextRetryTime,
        };
    }

    /**
     * Manually reset the circuit to closed state
     */
    reset() {
        this.transitionTo(CircuitState.CLOSED);
    }
}

/**
 * Error thrown when circuit is open
 */
class CircuitOpenError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CircuitOpenError';
    }
}

module.exports = CircuitBreaker;
module.exports.CircuitState = CircuitState;
module.exports.CircuitOpenError = CircuitOpenError;
