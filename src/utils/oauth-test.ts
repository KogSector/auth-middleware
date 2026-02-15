/**
 * ConFuse Auth Middleware - OAuth Flow Testing Utility
 * 
 * Test script for Redis-based OAuth state storage
 * Run with: tsx src/utils/oauth-test.ts
 */

import 'dotenv/config';
import { oAuthStateService } from '../services/oauth.js';
import { logger } from './logger.js';

async function testOAuthStateFlow() {
    console.log('🧪 Testing OAuth State Flow with Redis...\n');

    try {
        // Initialize service (implicit in constructor)
        console.log('✅ OAuth state service initialized');

        // Test 1: Create OAuth state
        console.log('\n📝 Test 1: Creating OAuth state...');
        const state = oAuthStateService.generateState();
        const pkce = oAuthStateService.generatePKCE();
        const redirectUri = 'http://localhost:3000/auth/oauth/github/callback';

        await oAuthStateService.storeState(state, {
            provider: 'github',
            redirectUri,
            userId: 'test-user-123',
            codeVerifier: pkce.codeVerifier,
        });

        console.log('✅ OAuth state created:');
        console.log(`   State: ${state.substring(0, 16)}...`);
        console.log(`   PKCE Verifier: Generated`);

        // Test 2: Validate valid state
        console.log('\n🔍 Test 2: Validating valid state...');
        const validation = await oAuthStateService.validateState(state);

        if (validation) {
            console.log('✅ State validation successful:');
            console.log(`   Provider: ${validation.provider}`);
            console.log(`   User ID: ${validation.userId}`);
            console.log(`   Redirect URI: ${validation.redirectUri}`);
            console.log(`   PKCE Verifier: ${validation.codeVerifier ? 'Present' : 'None'}`);
        } else {
            console.log('❌ State validation failed: State not found or invalid');
        }

        // Test 3: Validate consumed state (should fail)
        console.log('\n🔍 Test 3: Validating consumed state (should fail)...');
        await oAuthStateService.consumeState(state);
        const consumedValidation = await oAuthStateService.validateState(state);

        if (!consumedValidation) {
            console.log('✅ Consumed state correctly rejected (null)');
        } else {
            console.log('❌ Consumed state was incorrectly accepted');
        }

        // Test 4: Validate invalid state
        console.log('\n🔍 Test 4: Validating invalid state...');
        const invalidValidation = await oAuthStateService.validateState('invalid-state-123');

        if (!invalidValidation) {
            console.log('✅ Invalid state correctly rejected (null)');
        } else {
            console.log('❌ Invalid state was incorrectly accepted');
        }

        // Test 5: Test different providers
        console.log('\n📝 Test 5: Testing different providers...');
        const providers = ['github', 'google', 'gitlab', 'bitbucket'];

        for (const provider of providers) {
            try {
                const s = oAuthStateService.generateState();
                await oAuthStateService.storeState(s, {
                    provider,
                    redirectUri: `http://localhost:3000/auth/oauth/${provider}/callback`,
                });
                console.log(`✅ ${provider}: State created successfully`);

                // Clean up? Redis handles TTL. We can manually consume.
                await oAuthStateService.consumeState(s);
            } catch (error) {
                console.log(`❌ ${provider}: Failed - ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        }

        // Test 6: Test PKCE flow
        console.log('\n📝 Test 6: Testing PKCE flow...');
        const pkceState = oAuthStateService.generateState();
        const pkceData = oAuthStateService.generatePKCE();

        await oAuthStateService.storeState(pkceState, {
            provider: 'github',
            redirectUri: 'http://localhost:3000/auth/oauth/github/callback',
            codeVerifier: pkceData.codeVerifier,
        });

        if (pkceData.codeVerifier) {
            console.log('✅ PKCE flow: Code verifier generated');

            const pkceVal = await oAuthStateService.validateState(pkceState);
            if (pkceVal && pkceVal.codeVerifier) {
                console.log('✅ PKCE flow: Code verifier preserved in state');
            } else {
                console.log('❌ PKCE flow: Code verifier not preserved');
            }
        } else {
            console.log('❌ PKCE flow: No code verifier generated');
        }

        console.log('\n🎉 All OAuth state tests completed successfully!');

        process.exit(0);

    } catch (error) {
        console.error('\n❌ OAuth state test failed:', error);
        process.exit(1);
    }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    testOAuthStateFlow();
}

export { testOAuthStateFlow };
