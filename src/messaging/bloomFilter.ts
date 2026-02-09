/**
 * Bloom Filter for Deduplication - DSA Implementation
 * ====================================================
 *
 * Space-efficient probabilistic data structure for detecting duplicates.
 * Uses multiple hash functions for low false positive rates.
 *
 * Space Complexity: O(m) where m = number of bits
 * Time Complexity: O(k) for add/check where k = number of hash functions
 */

/**
 * Bloom filter implementation
 */
export default class BloomFilter {
    size: number;
    numHashes: number;
    bits: Uint8Array;
    itemCount: number;
    checks: number;
    positives: number;

    /**
     * Create a bloom filter
     * @param {number} expectedItems - Expected number of items
     * @param {number} falsePositiveRate - Acceptable false positive rate (0-1)
     */
    constructor(expectedItems: number = 100000, falsePositiveRate: number = 0.01) {
        // Calculate optimal size: m = -(n * ln(p)) / (ln(2)^2)
        this.size = Math.ceil(
            -(expectedItems * Math.log(falsePositiveRate)) / Math.pow(Math.log(2), 2)
        );

        // Calculate optimal hash count: k = (m/n) * ln(2)
        this.numHashes = Math.ceil((this.size / expectedItems) * Math.log(2));

        // Bit array (using Uint8Array for efficiency)
        this.bits = new Uint8Array(Math.ceil(this.size / 8));

        // Statistics
        this.itemCount = 0;
        this.checks = 0;
        this.positives = 0;
    }

    /**
     * Double hashing technique for generating k hash values
     * h(i) = (h1 + i * h2) mod m
     *
     * @param {string} item - Item to hash
     * @returns {number[]} Array of hash positions
     */
    getHashPositions(item: string): number[] {
        // Simple hash functions using djb2 and sdbm
        let h1 = 5381;
        let h2 = 0;

        for (let i = 0; i < item.length; i++) {
            const char = item.charCodeAt(i);
            h1 = ((h1 << 5) + h1) ^ char;
            h2 = char + (h2 << 6) + (h2 << 16) - h2;
        }

        h1 = Math.abs(h1);
        h2 = Math.abs(h2) | 1; // Ensure h2 is odd for better distribution

        const positions: number[] = [];
        for (let i = 0; i < this.numHashes; i++) {
            positions.push((h1 + i * h2) % this.size);
        }

        return positions;
    }

    /**
     * Get bit at position
     * @param {number} position - Bit position
     * @returns {boolean} Bit value
     */
    getBit(position: number): boolean {
        const byteIndex = Math.floor(position / 8);
        const bitIndex = position % 8;
        return (this.bits[byteIndex] & (1 << bitIndex)) !== 0;
    }

    /**
     * Set bit at position
     * @param {number} position - Bit position
     */
    setBit(position: number): void {
        const byteIndex = Math.floor(position / 8);
        const bitIndex = position % 8;
        this.bits[byteIndex] |= (1 << bitIndex);
    }

    /**
     * Add an item to the filter
     * @param {string} item - Item to add
     */
    add(item: string): void {
        const positions = this.getHashPositions(item);
        for (const pos of positions) {
            this.setBit(pos);
        }
        this.itemCount++;
    }

    /**
     * Check if item might be in the filter
     * @param {string} item - Item to check
     * @returns {boolean} True if might be present (could be false positive)
     */
    check(item: string): boolean {
        this.checks++;
        const positions = this.getHashPositions(item);
        const result = positions.every((pos) => this.getBit(pos));

        if (result) {
            this.positives++;
        }

        return result;
    }

    /**
     * Atomically check if item exists and add if not
     * @param {string} item - Item to check and possibly add
     * @returns {boolean} True if item was already present (duplicate)
     */
    checkAndAdd(item: string): boolean {
        const positions = this.getHashPositions(item);
        const exists = positions.every((pos) => this.getBit(pos));

        if (!exists) {
            for (const pos of positions) {
                this.setBit(pos);
            }
            this.itemCount++;
        }

        this.checks++;
        if (exists) {
            this.positives++;
        }

        return exists;
    }

    /**
     * Get filter statistics
     * @returns {Object} Statistics
     */
    getStats() {
        const fillRatio = (this.itemCount * this.numHashes) / this.size;
        const estimatedFP = Math.pow(1 - Math.exp(-fillRatio), this.numHashes);

        return {
            sizeBits: this.size,
            sizeBytes: this.bits.length,
            numHashes: this.numHashes,
            itemsAdded: this.itemCount,
            checks: this.checks,
            positives: this.positives,
            fillRatio,
            estimatedFalsePositiveRate: estimatedFP,
        };
    }

    /**
     * Serialize filter to Base64 for persistence
     * @returns {string} Base64 encoded filter
     */
    toBase64(): string {
        return Buffer.from(this.bits).toString('base64');
    }

    /**
     * Restore filter from Base64
     * @param {string} data - Base64 encoded filter
     * @param {number} expectedItems - Expected items (for sizing)
     * @param {number} falsePositiveRate - False positive rate
     * @returns {BloomFilter} Restored filter
     */
    static fromBase64(data: string, expectedItems: number, falsePositiveRate: number): BloomFilter {
        const filter = new BloomFilter(expectedItems, falsePositiveRate);
        const decoded = Buffer.from(data, 'base64');
        filter.bits = new Uint8Array(decoded);
        return filter;
    }
}

interface RotatingBloomFilterOptions {
    numBuckets?: number;
    expectedItems?: number;
    falsePositiveRate?: number;
}

/**
 * Rotating bloom filter with time-based expiry
 */
export class RotatingBloomFilter {
    numBuckets: number;
    expectedItems: number;
    falsePositiveRate: number;
    buckets: BloomFilter[];
    currentBucket: number;

    /**
     * Create a rotating bloom filter
     * @param {Object} options - Configuration
     */
    constructor(options: RotatingBloomFilterOptions = {}) {
        this.numBuckets = options.numBuckets || 3;
        this.expectedItems = options.expectedItems || 100000;
        this.falsePositiveRate = options.falsePositiveRate || 0.01;

        this.buckets = Array.from(
            { length: this.numBuckets },
            () => new BloomFilter(
                Math.ceil(this.expectedItems / this.numBuckets),
                this.falsePositiveRate
            )
        );
        this.currentBucket = 0;
    }

    /**
     * Rotate to next bucket (call periodically)
     */
    rotate(): void {
        this.currentBucket = (this.currentBucket + 1) % this.numBuckets;
        // Clear the bucket we're rotating into
        this.buckets[this.currentBucket] = new BloomFilter(
            Math.ceil(this.expectedItems / this.numBuckets),
            this.falsePositiveRate
        );
    }

    /**
     * Check and add across all buckets
     * @param {string} item - Item to check
     * @returns {boolean} True if duplicate found
     */
    checkAndAdd(item: string): boolean {
        // Check all buckets
        for (const bucket of this.buckets) {
            if (bucket.check(item)) {
                return true; // Duplicate found
            }
        }

        // Add to current bucket
        this.buckets[this.currentBucket].add(item);
        return false;
    }
}
