import { Redis } from 'ioredis';
import { logger } from '../utils/logger.js';
import { config } from '../config.js';

const falkordbHost = config.falkordbHost;
const falkordbPort = config.falkordbPort;
const falkordbUsername = config.falkordbUsername;
const falkordbPassword = config.falkordbPassword;

/**
 * Ensures that a FalkorDB graph is created and indexed for a new user.
 */
export async function createUserGraph(userId: string): Promise<void> {
  const graphName = `graph-${userId}`;
  
  logger.info(`Starting FalkorDB graph creation for user: ${userId}`, {
    graphName,
    host: falkordbHost,
    port: falkordbPort,
    username: falkordbUsername,
    hasPassword: !!falkordbPassword
  });
  
  const redis = new Redis({
    host: falkordbHost,
    port: falkordbPort,
    username: falkordbUsername,
    password: falkordbPassword,
    tls: falkordbHost.includes('aws') ? {} : undefined,
    connectTimeout: 10000, // 10 seconds connection timeout
    lazyConnect: false, // Connect immediately
    retryStrategy: (times: number) => {
      if (times > 3) {
        return null; // Stop retrying after 3 attempts
      }
      return Math.min(times * 200, 1000); // Exponential backoff
    },
  });

  try {
    logger.info(`Redis connection established, creating graph: ${graphName}`);
    
    // Create an index on Vector_Chunk to implicitly create the graph
    // (We'll also let the unified-processor ensure other indexes lazily if needed)
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (c:Vector_Chunk) ON (c.id)');
    logger.info(`Created Vector_Chunk.id index for ${graphName}`);
    
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (c:Vector_Chunk) ON (c.source_id)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (c:Vector_Chunk) ON (c.chunk_type)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (c:Vector_Chunk) ON (c.owner_id)');
    await redis.call('GRAPH.QUERY', graphName, "CREATE VECTOR INDEX FOR (c:Vector_Chunk) ON (c.embeddings) OPTIONS {dimension: 768, similarityFunction: 'cosine'}");
    
    // Code_Entity indexes
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (e:Code_Entity) ON (e.name)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (e:Code_Entity) ON (e.entity_type)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (e:Code_Entity) ON (e.source_id)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (e:Code_Entity) ON (e.qualified_name)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (e:Code_Entity) ON (e.owner_id)');
    
    // Web_Page and Repository indexes
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (p:Web_Page) ON (p.url)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (p:Web_Page) ON (p.domain)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (p:Web_Page) ON (p.source_id)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (p:Web_Page) ON (p.owner_id)');
    await redis.call('GRAPH.QUERY', graphName, 'CREATE INDEX FOR (r:Repository) ON (r.owner_id)');
    
    logger.info(`Successfully initialized graph ${graphName}`);
  } catch (error: any) {
    // If the index already exists, it will throw an error, which is safe to ignore
    if (error.message && error.message.includes('Index already exists')) {
      logger.info(`Graph indexes already exist for ${graphName}`);
    } else {
      logger.error(`Error initializing FalkorDB graph for user ${userId}:`, {
        error: error.message,
        stack: error.stack
      });
    }
  } finally {
    redis.disconnect();
    logger.info(`Redis connection closed for ${graphName}`);
  }
}

/**
 * Deletes a FalkorDB graph for a user, dropping all nodes and edges.
 */
export async function deleteUserGraph(userId: string): Promise<void> {
  const graphName = `graph-${userId}`;
  
  const redis = new Redis({
    host: falkordbHost,
    port: falkordbPort,
    username: falkordbUsername,
    password: falkordbPassword,
    tls: falkordbHost.includes('aws') ? {} : undefined,
    connectTimeout: 10000, // 10 seconds connection timeout
    lazyConnect: false, // Connect immediately
    retryStrategy: (times: number) => {
      if (times > 3) {
        return null; // Stop retrying after 3 attempts
      }
      return Math.min(times * 200, 1000); // Exponential backoff
    },
  });

  try {
    logger.info(`Deleting FalkorDB graph for user: ${userId} (${graphName})`);
    
    // GRAPH.DELETE will completely remove the graph and all its data
    await redis.call('GRAPH.DELETE', graphName);
    
    logger.info(`Successfully deleted graph ${graphName}`);
  } catch (error: any) {
    // If the graph doesn't exist, it's fine. We log it but don't fail.
    if (error.message && error.message.includes('Invalid graph name')) {
      logger.info(`Graph ${graphName} did not exist, nothing to delete.`);
    } else {
      logger.error(`Error deleting FalkorDB graph for user ${userId}:`, error);
    }
  } finally {
    redis.disconnect();
  }
}
