import { config } from '../config.js';
import { logger } from '../utils/logger.js';

interface ToggleData {
    name: string;
    enabled: boolean;
    category: string;
}

export class FeatureToggleClient {
    private static instance: FeatureToggleClient;
    private cache: Map<string, { value: boolean; expiresAt: number }> = new Map();
    private readonly CACHE_TTL_MS = 60000; // 1 minute

    private constructor() {}

    static getInstance(): FeatureToggleClient {
        if (!FeatureToggleClient.instance) {
            FeatureToggleClient.instance = new FeatureToggleClient();
        }
        return FeatureToggleClient.instance;
    }

    async isEnabled(toggleName: string): Promise<boolean> {
        // Check cache
        const cached = this.cache.get(toggleName);
        if (cached && Date.now() < cached.expiresAt) {
            return cached.value;
        }

        try {
            const response = await fetch(`${config.featureToggleServiceUrl}/api/toggles/${toggleName}`);
            if (!response.ok) {
                // If 404 or other error, default to false
                this.setCache(toggleName, false);
                return false;
            }

            const data: ToggleData = await response.json();
            const isEnabled = Boolean(data.enabled);
            
            // In production, devOnly toggles should ALWAYS be disabled.
            // We assume category 'devOnly' is what we want to disable.
            if (config.nodeEnv === 'production' && data.category === 'devOnly') {
                this.setCache(toggleName, false);
                return false;
            }

            this.setCache(toggleName, isEnabled);
            return isEnabled;
        } catch (error) {
            // Default to false if service is down
            logger.warn(`[FEATURE-TOGGLE] Failed to fetch toggle ${toggleName}, defaulting to false`, { 
                error: error instanceof Error ? error.message : 'Unknown' 
            });
            this.setCache(toggleName, false);
            return false;
        }
    }

    private setCache(name: string, value: boolean) {
        this.cache.set(name, {
            value,
            expiresAt: Date.now() + this.CACHE_TTL_MS
        });
    }
}
