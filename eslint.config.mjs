import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

// ESLint v9+ flat config (replaces the legacy .eslintrc.cjs).
// Kept dependency-free: only the already-installed @typescript-eslint packages
// are imported. `no-undef` is disabled because the TypeScript compiler
// already catches undefined identifiers.
export default [
    {
        ignores: ['dist/**', 'node_modules/**', 'logs/**'],
    },
    {
        files: ['src/**/*.{ts,js}'],
        languageOptions: {
            parser: tsParser,
            ecmaVersion: 2021,
            sourceType: 'module',
            parserOptions: {
                project: './tsconfig.json',
            },
        },
        plugins: {
            '@typescript-eslint': tsPlugin,
        },
        rules: {
            'no-undef': 'off',
            'no-unused-vars': 'off',
            '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
            '@typescript-eslint/no-explicit-any': 'warn',
            'no-console': 'off',
        },
    },
];