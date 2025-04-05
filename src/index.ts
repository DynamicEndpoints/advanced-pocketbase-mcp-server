#!/usr/bin/env node
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import PocketBase from 'pocketbase';
import { z } from 'zod';
import { EventSource } from 'eventsource'; // Import the polyfill using named import

// Assign the polyfill to the global scope for PocketBase SDK to find
// @ts-ignore - Need to assign to global scope
global.EventSource = EventSource;

// Define types for PocketBase
interface CollectionModel {
  id: string;
  name: string;
  type: string;
  system: boolean;
  schema: SchemaField[];
  listRule: string | null;
  viewRule: string | null;
  createRule: string | null;
  updateRule: string | null;
  deleteRule: string | null;
  indexes?: Array<{
    name: string;
    fields: string[];
    unique?: boolean;
  }>;
}

interface RecordModel {
  id: string;
  [key: string]: any;
}

interface ListResult<T> {
  page: number;
  perPage: number;
  totalItems: number;
  totalPages: number;
  items: T[];
}

interface RequestHandlerExtra {
  [key: string]: any;
}

// Extend PocketBase types
interface ExtendedPocketBase extends PocketBase {
  baseUrl: string;
  authStore: { // Restore explicit authStore definition
    isValid: boolean;
    token: string;
    model: any;
    save(token: string, model: any): void;
    clear(): void;
    exportToCookie(options?: any): string;
    loadFromCookie(cookie: string): void;
  };
  admins: any; // Add admins collection service type (using 'any' for simplicity)
  collections: {
    getList(page?: number, perPage?: number, options?: any): Promise<any>;
    getOne(id: string): Promise<any>;
    create(data: any): Promise<any>;
    update(id: string, data: any): Promise<any>;
    delete(id: string): Promise<any>;
  };
  filter(expr: string, params: Record<string, any>): string;
  autoCancellation(enable: boolean): void;
  cancelRequest(key: string): void;
}

// Schema field type
interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  options?: Record<string, any>;
}

// Schema field from input
interface InputSchemaField {
  name: string;
  type: string;
  required?: boolean;
  options?: Record<string, any>;
}

// Type for subscription event (adjust based on actual PocketBase SDK types if known)
interface SubscriptionEvent {
	action: string;
	record: RecordModel;
}


class PocketBaseServer {
  private server: McpServer;
  private pb: ExtendedPocketBase;
  private _customHeaders: Record<string, string> = {};

  constructor() {
    this.server = new McpServer({
      name: 'pocketbase-server',
      version: '0.1.0',
    });

    // Initialize PocketBase client
    const url = process.env.POCKETBASE_URL;
    if (!url) {
      throw new Error('POCKETBASE_URL environment variable is required');
    }
    this.pb = new PocketBase(url) as unknown as ExtendedPocketBase;

    this.setupTools();
    this.setupResources();
    this.setupPrompts();
    
    // Error handling
    process.on('SIGINT', async () => {
      process.exit(0);
    });
  }

  private setupPrompts() {
    // Collection creation prompt
    this.server.prompt(
      "create-collection",
      "Create a new collection with specified fields",
      async (extra: RequestHandlerExtra) => ({
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Create a new collection with specified fields`
          }
        }]
      })
    );

    // Record creation prompt
    this.server.prompt(
      "create-record",
      "Create a new record in a collection",
      async (extra: RequestHandlerExtra) => ({
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Create a new record in a collection`
          }
        }]
      })
    );

    // Query builder prompt
    this.server.prompt(
      "build-query",
      "Build a query for a collection with filters, sorting, and expansion",
      async (extra: RequestHandlerExtra) => ({
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Build a query for a collection with filters, sorting, and expansion`
          }
        }]
      })
    );
  }

  private setupResources() {
    interface CollectionInfo {
      id: string;
      name: string;
      type: string;
      system: boolean;
      listRule: string | null;
      viewRule: string | null;
      createRule: string | null;
      updateRule: string | null;
      deleteRule: string | null;
    }

    interface CollectionRecord {
      id: string;
      [key: string]: any;
    }

    // Server info resource
    this.server.resource(
      "server-info",
      "pocketbase://info",
      async (uri) => {
        try {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({
                url: this.pb.baseUrl,
                isAuthenticated: this.pb.authStore?.isValid || false
              }, null, 2)
            }]
          };
        } catch (error: any) {
          throw new Error(`Failed to get server info: ${error.message}`);
        }
      }
    );

    // Collection schema resource
    this.server.resource(
      "collection-schema",
      new ResourceTemplate("pocketbase://collections/{name}/schema", { list: undefined }),
      async (uri, params) => {
        const name = typeof params.name === 'string' ? params.name : params.name[0];
        try {
          const collection = await this.pb.collections.getOne(name);
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify(collection.schema, null, 2)
            }]
          };
        } catch (error: any) {
          throw new Error(`Failed to get collection schema: ${error.message}`);
        }
      }
    );

    // Collection list resource
    this.server.resource(
      "collections",
      "pocketbase://collections",
      async (uri) => {
        try {
          const collectionsResponse = await this.pb.collections.getList(1, 100);
          const collections = {
            page: collectionsResponse.page,
            perPage: collectionsResponse.perPage,
            totalItems: collectionsResponse.totalItems,
            totalPages: collectionsResponse.totalPages,
            items: collectionsResponse.items as unknown as CollectionModel[]
          };
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify(collections.items.map(c => ({
                id: c.id,
                name: c.name,
                type: c.type,
                system: c.system,
                listRule: c.listRule,
                viewRule: c.viewRule,
                createRule: c.createRule,
                updateRule: c.updateRule,
                deleteRule: c.deleteRule,
              })), null, 2)
            }]
          };
        } catch (error: any) {
          throw new Error(`Failed to list collections: ${error.message}`);
        }
      }
    );

    // Record resource
    this.server.resource(
      "record",
      new ResourceTemplate("pocketbase://collections/{collection}/records/{id}", { list: undefined }),
      async (uri, params) => {
        const collection = typeof params.collection === 'string' ? params.collection : params.collection[0];
        const id = typeof params.id === 'string' ? params.id : params.id[0];
        try {
          // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
          const record = await this.pb.collection(collection).getOne(id) as RecordModel;
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify(record, null, 2)
            }]
          };
        } catch (error: any) {
          throw new Error(`Failed to get record: ${error.message}`);
        }
      }
    );

    // Auth info resource
    this.server.resource(
      "auth-info",
      "pocketbase://auth",
      async (uri) => {
        try {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({
                isValid: this.pb.authStore.isValid,
                token: this.pb.authStore.token,
                model: this.pb.authStore.model
              }, null, 2)
            }]
          };
        } catch (error: any) {
          throw new Error(`Failed to get auth info: ${error.message}`);
        }
      }
    );
  }

  private setupTools() {
    // Server info tool
    this.server.tool(
      'get_server_info',
      {},
      async () => {
        try {
          return {
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                url: this.pb.baseUrl,
                isAuthenticated: this.pb.authStore?.isValid || false,
                version: '0.1.0'
              }, null, 2) 
            }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to get server info: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Auth info tool
    this.server.tool(
      'get_auth_info',
      {},
      async () => {
        try {
          return {
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                isValid: this.pb.authStore.isValid,
                token: this.pb.authStore.token,
                model: this.pb.authStore.model
              }, null, 2) 
            }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to get auth info: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // New tool to list all collections
    this.server.tool(
      'list_collections',
      {
        includeSystem: z.boolean().optional().default(false).describe('Whether to include system collections')
      },
      async ({ includeSystem }) => {
        try {
          // Try to get collections without authentication first
          try {
            const collections = await this.pb.collections.getList(1, 100);
            const filteredCollections = includeSystem 
              ? collections.items 
              : collections.items.filter((c: any) => !c.system);
            
            return {
              content: [{ 
                type: 'text', 
                text: JSON.stringify(filteredCollections.map((c: any) => ({
                  id: c.id,
                  name: c.name,
                  type: c.type,
                  system: c.system,
                  recordCount: c.recordCount || 0
                })), null, 2) 
              }]
            };
          } catch (error: any) {
            // If authentication is required, try to discover collections by testing common ones
            // and by checking which ones are accessible
            const commonCollections = ['users', 'products', 'posts', 'categories', 'orders', 'customers', 'items', 'files'];
            const discoveredCollections = [];
            
            for (const collectionName of commonCollections) {
              try {
                // Try to list records in this collection
                const result = await this.pb.collection(collectionName).getList(1, 1);
                discoveredCollections.push({
                  name: collectionName,
                  recordCount: result.totalItems
                });
              } catch (e) {
                // Skip collections that don't exist or require authentication
              }
            }
            
            return {
              content: [{ 
                type: 'text', 
                text: JSON.stringify(discoveredCollections, null, 2) 
              }]
            };
          }
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to list collections: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Record management tools
    this.server.tool(
      'create_record',
      {
        collection: z.string().describe('Collection name'),
        data: z.record(z.any()).describe('Record data')
      },
      async ({ collection, data }) => {
        try {
          const result = await this.pb.collection(collection).create(data);
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to create record: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Collection management tools
    this.server.tool(
      'create_collection',
      {
        name: z.string().describe('Collection name'),
        schema: z.array(z.object({
          name: z.string(),
          type: z.string(),
          required: z.boolean().optional(),
          options: z.record(z.any()).optional()
        })).describe('Collection schema')
      },
      async ({ name, schema }) => {
        try {
          // Convert schema to ensure required is always defined
          const processedSchema = schema.map(field => ({
            ...field,
            required: field.required === undefined ? false : field.required
          }));
          
          const result = await this.pb.collections.create({
            name,
            schema: processedSchema
          });
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to create collection: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'list_records',
      {
        collection: z.string().describe('Collection name'),
        filter: z.string().optional().describe('Filter query'),
        sort: z.string().optional().describe('Sort field and direction'),
        page: z.number().optional().describe('Page number'),
        perPage: z.number().optional().describe('Items per page')
      },
      async ({ collection, filter, sort, page = 1, perPage = 50 }) => {
        try {
          const options: any = {};
          if (filter) options.filter = filter;
          if (sort) options.sort = sort;

          const result = await this.pb.collection(collection).getList(page, perPage, options);
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to list records: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'update_record',
      {
        collection: z.string().describe('Collection name'),
        id: z.string().describe('Record ID'),
        data: z.record(z.any()).describe('Updated record data')
      },
      async ({ collection, id, data }) => {
        try {
          const result = await this.pb.collection(collection).update(id, data);
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to update record: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'delete_record',
      {
        collection: z.string().describe('Collection name'),
        id: z.string().describe('Record ID')
      },
      async ({ collection, id }) => {
        try {
          await this.pb.collection(collection).delete(id);
          return {
            content: [{ type: 'text', text: `Successfully deleted record ${id} from collection ${collection}` }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to delete record: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Authentication tools
    this.server.tool(
      'authenticate_user',
      {
        // Make email and password optional to allow using env vars when isAdmin is true
        email: z.string().optional().describe('User email (required unless isAdmin=true and env vars are set)'),
        password: z.string().optional().describe('User password (required unless isAdmin=true and env vars are set)'),
        collection: z.string().optional().default('users').describe('Collection name'),
        isAdmin: z.boolean().optional().default(false).describe('Whether to authenticate as an admin')
      },
      async ({ email, password, collection, isAdmin }) => {
        try {
          const authCollection = isAdmin ? '_superusers' : collection;
          const authEmail = isAdmin && !email ? process.env.POCKETBASE_ADMIN_EMAIL : email;
          const authPassword = isAdmin && !password ? process.env.POCKETBASE_ADMIN_PASSWORD : password;
          
          if (!authEmail || !authPassword) {
            return {
              content: [{ type: 'text', text: 'Email and password are required for authentication' }],
              isError: true
            };
          }
          
          const authData = await this.pb
            .collection(authCollection)
            .authWithPassword(authEmail, authPassword);
          
          return {
            content: [{ type: 'text', text: JSON.stringify(authData, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Authentication failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'authenticate_with_oauth2',
      {
        provider: z.string().describe('OAuth2 provider name'),
        code: z.string().describe('Authorization code'),
        codeVerifier: z.string().describe('PKCE code verifier'),
        redirectUrl: z.string().describe('Redirect URL'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ provider, code, codeVerifier, redirectUrl, collection }) => {
        try {
          const authData = await this.pb
            .collection(collection)
            .authWithOAuth2(provider, code, codeVerifier, redirectUrl);
          
          return {
            content: [{ type: 'text', text: JSON.stringify(authData, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `OAuth2 authentication failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'authenticate_with_otp',
      {
        email: z.string().describe('User email'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ email, collection }) => {
        try {
          const result = await this.pb.collection(collection).authWithOtp(email);
          return {
            content: [{ type: 'text', text: JSON.stringify({ success: result }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `OTP authentication failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'auth_refresh',
      {
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ collection }) => {
        try {
          const authData = await this.pb.collection(collection).authRefresh();
          return {
            content: [{ type: 'text', text: JSON.stringify(authData, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Auth refresh failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Email verification tools
    this.server.tool(
      'request_verification',
      {
        email: z.string().describe('User email'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ email, collection }) => {
        try {
          const result = await this.pb.collection(collection).requestVerification(email);
          return {
            content: [{ type: 'text', text: JSON.stringify({ success: result }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Verification request failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'confirm_verification',
      {
        token: z.string().describe('Verification token'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ token, collection }) => {
        try {
          const result = await this.pb.collection(collection).confirmVerification(token);
          return {
            content: [{ type: 'text', text: JSON.stringify({ success: result }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Verification confirmation failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Password reset tools
    this.server.tool(
      'request_password_reset',
      {
        email: z.string().describe('User email'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ email, collection }) => {
        try {
          const result = await this.pb.collection(collection).requestPasswordReset(email);
          return {
            content: [{ type: 'text', text: JSON.stringify({ success: result }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Password reset request failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'confirm_password_reset',
      {
        token: z.string().describe('Reset token'),
        password: z.string().describe('New password'),
        passwordConfirm: z.string().describe('Confirm new password'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ token, password, passwordConfirm, collection }) => {
        try {
          const result = await this.pb.collection(collection).confirmPasswordReset(token, password, passwordConfirm);
          return {
            content: [{ type: 'text', text: JSON.stringify({ success: result }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Password reset confirmation failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Email change tools
    this.server.tool(
      'request_email_change',
      {
        newEmail: z.string().describe('New email address'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ newEmail, collection }) => {
        try {
          const result = await this.pb.collection(collection).requestEmailChange(newEmail);
          return {
            content: [{ type: 'text', text: JSON.stringify({ success: result }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Email change request failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'confirm_email_change',
      {
        token: z.string().describe('Email change token'),
        password: z.string().describe('Current password for confirmation'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ token, password, collection }) => {
        try {
          const authData = await this.pb.collection(collection).confirmEmailChange(token, password);
          return {
            content: [{ type: 'text', text: JSON.stringify(authData, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Email change confirmation failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // User management tools
    this.server.tool(
      'impersonate_user',
      {
        userId: z.string().describe('ID of the user to impersonate'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ userId, collection }) => {
        try {
          const authData = await this.pb.collection(collection).impersonate(userId);
          return {
            content: [{ type: 'text', text: JSON.stringify(authData, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `User impersonation failed: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'create_user',
      {
        email: z.string().describe('User email'),
        password: z.string().describe('User password'),
        passwordConfirm: z.string().describe('Password confirmation'),
        name: z.string().optional().describe('User name'),
        collection: z.string().optional().default('users').describe('Collection name')
      },
      async ({ email, password, passwordConfirm, name, collection }) => {
        try {
          const result = await this.pb.collection(collection).create({
            email,
            password,
            passwordConfirm,
            name,
          });
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to create user: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Record tools
    this.server.tool(
      'get_record',
      {
        collection: z.string().describe('Collection name'),
        id: z.string().describe('Record ID'),
        expand: z.string().optional().describe('Relations to expand')
      },
      async ({ collection, id, expand }) => {
        try {
          const options: any = {};
          if (expand) options.expand = expand;
          
          // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
          const record = await this.pb.collection(collection).getOne(id, options);
          return {
            content: [{ type: 'text', text: JSON.stringify(record, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to get record: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Tool to set collection access rules
    this.server.tool(
      'set_collection_rules',
      {
        collection: z.string().describe('Collection name or ID'),
        listRule: z.string().nullable().optional().describe('List rule (PocketBase filter syntax or null)'),
        viewRule: z.string().nullable().optional().describe('View rule (PocketBase filter syntax or null)'),
        createRule: z.string().nullable().optional().describe('Create rule (PocketBase filter syntax or null)'),
        updateRule: z.string().nullable().optional().describe('Update rule (PocketBase filter syntax or null)'),
        deleteRule: z.string().nullable().optional().describe('Delete rule (PocketBase filter syntax or null)')
      },
      async ({ collection, listRule, viewRule, createRule, updateRule, deleteRule }) => {
        try {
          // Construct the update payload, only including rules that were provided
          const payload: Record<string, string | null> = {};
          if (listRule !== undefined) payload.listRule = listRule;
          if (viewRule !== undefined) payload.viewRule = viewRule;
          if (createRule !== undefined) payload.createRule = createRule;
          if (updateRule !== undefined) payload.updateRule = updateRule;
          if (deleteRule !== undefined) payload.deleteRule = deleteRule;

          if (Object.keys(payload).length === 0) {
             return {
               content: [{ type: 'text', text: 'No rules provided to update.' }],
               isError: true
             };
          }

          // Updating rules typically requires admin privileges
          const result = await this.pb.collections.update(collection, payload);
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          // Catch permission errors or other issues
          return {
            content: [{ type: 'text', text: `Failed to set collection rules: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Tool to update collection schema (add/remove/update fields)
    this.server.tool(
      'update_collection_schema',
      {
        collection: z.string().describe('Collection name or ID'),
        addFields: z.array(z.object({
          name: z.string(),
          type: z.string(),
          required: z.boolean().optional().default(false),
          options: z.record(z.any()).optional()
        })).optional().describe('Fields to add'),
        removeFields: z.array(z.string()).optional().describe('Names of fields to remove'),
        updateFields: z.array(z.object({
          name: z.string().describe('Name of the field to update'),
          newName: z.string().optional().describe('Optional new name for the field'),
          type: z.string().optional().describe('Optional new type'),
          required: z.boolean().optional().describe('Optional new required status'),
          options: z.record(z.any()).optional().describe('Optional new options')
        })).optional().describe('Fields to update')
      },
      async ({ collection, addFields = [], removeFields = [], updateFields = [] }) => {
        try {
          // Fetch the current collection details including schema
          const currentCollection = await this.pb.collections.getOne(collection);
          let currentSchema: SchemaField[] = currentCollection.schema || [];

          // Process removals first
          if (removeFields.length > 0) {
            currentSchema = currentSchema.filter(field => !removeFields.includes(field.name));
          }

          // Process updates
          if (updateFields.length > 0) {
            currentSchema = currentSchema.map(field => {
              const updateInfo = updateFields.find(uf => uf.name === field.name);
              if (updateInfo) {
                return {
                  ...field,
                  name: updateInfo.newName ?? field.name, // Update name if provided
                  type: updateInfo.type ?? field.type, // Update type if provided
                  required: updateInfo.required ?? field.required, // Update required status if provided
                  options: updateInfo.options ?? field.options // Update options if provided
                };
              }
              return field;
            });
          }

          // Process additions
          if (addFields.length > 0) {
             const processedAddFields = addFields.map(field => ({
               ...field,
               required: field.required ?? false // Ensure required has a default
             }));
            currentSchema = [...currentSchema, ...processedAddFields];
          }

          // Update the collection with the modified schema
          // Note: This replaces the entire schema. Requires admin privileges.
          const result = await this.pb.collections.update(collection, { schema: currentSchema });
          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };

        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to update collection schema: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Tool to get collection schema (duplicates resource functionality for tool access)
    this.server.tool(
      'get_collection_schema',
      {
        collection: z.string().describe('Collection name or ID')
      },
      async ({ collection }) => {
        try {
          // First, try the direct SDK call
          const collectionData = await this.pb.collections.getOne(collection);
          return {
            content: [{ type: 'text', text: JSON.stringify(collectionData.schema || [], null, 2) }]
          };
        } catch (error: any) {
          // If direct access fails due to auth, try inferring from a record
          if (error.status === 403 || error.status === 401 || (error.message && (error.message.includes("authorization") || error.message.includes("permission")))) {
            try {
              const records = await this.pb.collection(collection).getList(1, 1, { $autoCancel: false }); // Use different request key potentially
              if (records.items.length > 0) {
                const record = records.items[0];
                // Basic inference logic (might not capture all details like options, required status accurately)
                const inferredSchema = Object.keys(record)
                  .filter(key => !['id', 'created', 'updated', 'collectionId', 'collectionName', 'expand'].includes(key)) // Filter out common system fields
                  .map(field => ({
                    name: field,
                    type: typeof record[field] === 'object' ? 'json' : typeof record[field], // Basic type detection
                    required: false, // Cannot reliably infer required status
                    system: false, // Assume not system field
                    options: {} // Cannot infer options
                  }));
                return {
                  content: [{
                    type: 'text',
                    text: JSON.stringify(inferredSchema, null, 2) + "\n\nNote: This schema was inferred from record data as direct schema access failed (likely due to permissions). Details like 'required' status or field options might be inaccurate."
                  }]
                };
              } else {
                 // If no records, we can't infer
                 return {
                   content: [{ type: 'text', text: `Failed to get collection schema: ${error.message}. Attempted inference failed as the collection appears empty.` }],
                   isError: true
                 };
              }
            } catch (inferenceError: any) {
              // If inference also fails, return the original error plus inference error
              return {
                content: [{ type: 'text', text: `Failed to get collection schema: ${error.message}. Attempted inference also failed: ${inferenceError.message}` }],
                isError: true
              };
            }
          }
          // If it's a different error (e.g., collection not found), return that
          return {
            content: [{ type: 'text', text: `Failed to get collection schema: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Collection schema tools (This comment seems redundant now, removing)

    // Database management tools
    this.server.tool(
      'backup_database',
      {
        format: z.enum(['json', 'csv']).optional().default('json').describe('Export format')
      },
      async ({ format }) => {
        try {
          const collections = await this.pb.collections.getList(1, 100);
          const backup: any = {};

          for (const collection of collections.items) {
            const records = await this.pb.collection(collection.name).getFullList();
            backup[collection.name] = {
              schema: collection.schema,
              records,
            };
          }

          if (format === 'csv') {
            let csv = '';
            for (const [collectionName, data] of Object.entries(backup)) {
              const { schema, records } = data as { schema: any[], records: any[] };
              csv += `Collection: ${collectionName}\n`;
              csv += `Schema:\n${JSON.stringify(schema, null, 2)}\n`;
              csv += 'Records:\n';
              if (records.length > 0) {
                const headers = Object.keys(records[0]);
                csv += headers.join(',') + '\n';
                records.forEach((record) => {
                  csv += headers.map(header => JSON.stringify(record[header])).join(',') + '\n';
                });
              }
              csv += '\n';
            }
            return {
              content: [{ type: 'text', text: csv }]
            };
          }

          return {
            content: [{ type: 'text', text: JSON.stringify(backup, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to backup database: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    this.server.tool(
      'import_data',
      {
        collection: z.string().describe('Collection name'),
        data: z.array(z.record(z.any())).describe('Array of records to import'),
        mode: z.enum(['create', 'update', 'upsert']).optional().default('create').describe('Import mode')
      },
      async ({ collection, data, mode }) => {
        try {
          const results = [];
          for (const record of data) {
            let result;
            switch (mode) {
              case 'create':
                result = await this.pb.collection(collection).create(record);
                break;
              case 'update':
                if (!record.id) {
                  throw new Error('Record ID required for update mode');
                }
                result = await this.pb.collection(collection).update(record.id, record);
                break;
              case 'upsert':
                if (record.id) {
                  try {
                    result = await this.pb.collection(collection).update(record.id, record);
                  } catch {
                    result = await this.pb.collection(collection).create(record);
                  }
                } else {
                  result = await this.pb.collection(collection).create(record);
                }
                break;
            }
            results.push(result);
          }

          return {
            content: [{ type: 'text', text: JSON.stringify(results, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to import data: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Collection migration tool
    this.server.tool(
      'migrate_collection',
      {
        collection: z.string().describe('Collection name'),
        newSchema: z.array(z.object({
          name: z.string(),
          type: z.string(),
          required: z.boolean().default(false),
          options: z.record(z.any()).optional()
        })).describe('New collection schema'),
        dataTransforms: z.record(z.string()).optional().describe('Field transformation mappings')
      },
      async ({ collection, newSchema, dataTransforms }) => {
        try {
          console.error(`[MCP PocketBase WARNING] Executing 'migrate_collection' for '${collection}'. This tool is risky! It deletes the original collection before migration is fully complete. Backup your data first.`);
          const tempName = `${collection}_migration_${Date.now()}`;
          // Convert schema to ensure required is always defined
          const processedSchema = newSchema.map(field => ({
            ...field,
            required: field.required === undefined ? false : field.required
          }));
          
          await this.pb.collections.create({
            name: tempName,
            schema: processedSchema,
          });

          const oldRecords = await this.pb.collection(collection).getFullList();
          const transformedRecords = oldRecords.map(record => {
            const newRecord: any = { ...record };
            if (dataTransforms) {
              for (const [field, transform] of Object.entries(dataTransforms)) {
                try {
                  newRecord[field] = new Function('oldValue', `return ${transform}`)(record[field]);
                } catch (e) {
                  console.error(`Failed to transform field ${field}:`, e);
                }
              }
            }
            return newRecord;
          });

          for (const record of transformedRecords) {
            await this.pb.collection(tempName).create(record);
          }

          await this.pb.collections.delete(collection);
          const renamedCollection = await this.pb.collections.update(tempName, {
            name: collection,
          });

          return {
            content: [{ type: 'text', text: JSON.stringify(renamedCollection, null, 2) + "\n\nWARNING: Migration completed, but this tool's process involves deleting the original collection before renaming the new one, which carries a risk of data loss if errors occur during the final steps. Ensure you have backups." }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to migrate collection: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Advanced query tool
    this.server.tool(
      'query_collection',
      {
        collection: z.string().describe('Collection name'),
        filter: z.string().optional().describe('Filter expression'),
        sort: z.string().optional().describe('Sort expression'),
        expand: z.string().optional().describe('Relations to expand'),
        aggregate: z.record(z.string()).optional().describe('Aggregation settings')
      },
      async ({ collection, filter, sort, expand, aggregate }) => {
        try {
          const options: any = {};
          if (filter) options.filter = filter;
          if (sort) options.sort = sort;
          if (expand) options.expand = expand;

          const records = await this.pb.collection(collection).getList(1, 100, options);
          let result: any = { items: records.items };

          if (aggregate) {
            const aggregations: any = {};
            for (const [name, expr] of Object.entries(aggregate)) {
              const [func, field] = expr.split('(');
              const cleanField = field.replace(')', '');
              
              switch (func) {
                case 'sum':
                  aggregations[name] = records.items.reduce((sum: number, record: any) => 
                    sum + (parseFloat(record[cleanField]) || 0), 0);
                  break;
                case 'avg':
                  aggregations[name] = records.items.reduce((sum: number, record: any) => 
                    sum + (parseFloat(record[cleanField]) || 0), 0) / records.items.length;
                  break;
                case 'count':
                  aggregations[name] = records.items.length;
                  break;
                default:
                  return {
                    content: [{ type: 'text', text: `Unsupported aggregation function: ${func}` }],
                    isError: true
                  };
              }
            }
            result.aggregations = aggregations;
          }

          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to query collection: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Index management tool
    this.server.tool(
      'manage_indexes',
      {
        collection: z.string().describe('Collection name'),
        action: z.enum(['create', 'delete', 'list']).describe('Action to perform'),
        index: z.object({
          name: z.string(),
          fields: z.array(z.string()),
          unique: z.boolean().optional()
        }).optional().describe('Index configuration (for create)')
      },
      async ({ collection, action, index }) => {
        try {
          const collectionObj = await this.pb.collections.getOne(collection);
          const currentIndexes = collectionObj.indexes || [];
          let result;

          switch (action) {
            case 'create':
              if (!index) {
                return {
                  content: [{ type: 'text', text: 'Index configuration required for create action' }],
                  isError: true
                };
              }
              const updatedCollection = await this.pb.collections.update(collectionObj.id, {
                ...collectionObj,
                indexes: [...currentIndexes, index],
              });
              result = updatedCollection.indexes;
              break;

            case 'delete':
              if (!index?.name) {
                return {
                  content: [{ type: 'text', text: 'Index name required for delete action' }],
                  isError: true
                };
              }
              const filteredIndexes = currentIndexes.filter((idx: any) => idx.name !== index.name);
              const collectionAfterDelete = await this.pb.collections.update(collectionObj.id, {
                ...collectionObj,
                indexes: filteredIndexes,
              });
              result = collectionAfterDelete.indexes;
              break;

            case 'list':
              result = currentIndexes;
              break;
          }

          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to manage indexes: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // File upload tool
    this.server.tool(
      'upload_file',
      {
        collection: z.string().describe('Collection name'),
        recordId: z.string().optional().describe('Record ID (optional - if not provided, creates new record)'),
        fileData: z.object({
          name: z.string().describe('File name'),
          content: z.string().describe('Base64 encoded file content'),
          type: z.string().optional().describe('File MIME type')
        }).describe('File data in base64 format'),
        additionalFields: z.record(z.any()).optional().describe('Additional record fields')
      },
      async ({ collection, recordId, fileData, additionalFields = {} }) => {
        try {
          const binaryData = Buffer.from(fileData.content, 'base64');
          const blob = new Blob([binaryData], { type: fileData.type || 'application/octet-stream' });
          
          const formData = new FormData();
          formData.append(fileData.name, blob, fileData.name);
          
          Object.entries(additionalFields).forEach(([key, value]) => {
            formData.append(key, value as string);
          });

          let result;
          if (recordId) {
            result = await this.pb.collection(collection).update(recordId, formData);
          } else {
            result = await this.pb.collection(collection).create(formData);
          }

          return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to upload file: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Filter builder tool
    this.server.tool(
      'build_filter',
      {
        expression: z.string().describe('Filter expression with placeholders'),
        params: z.record(z.any()).describe('Parameter values')
      },
      async ({ expression, params }) => {
        try {
          // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
          const filter = this.pb.filter(expression, params);
          return {
            content: [{ type: 'text', text: JSON.stringify({ filter }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to build filter: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Request options tool
    this.server.tool(
      'set_request_options',
      {
        autoCancellation: z.boolean().optional().describe('Enable/disable auto cancellation'),
        requestKey: z.string().nullable().optional().describe('Custom request identifier'),
        headers: z.record(z.string()).optional().describe('Custom headers')
      },
      async ({ autoCancellation, requestKey, headers }) => {
        try {
          if (typeof autoCancellation === 'boolean') {
            // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
            this.pb.autoCancellation(autoCancellation);
          }

          if (requestKey === null) {
            // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
            this.pb.cancelRequest(requestKey);
          }

          if (headers) {
            this._customHeaders = headers;
          }

          return {
            content: [{ type: 'text', text: JSON.stringify({ success: true }, null, 2) }]
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to set request options: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Auth store management tool
    this.server.tool(
      'manage_auth_store',
      {
        action: z.enum(['save', 'clear', 'export_cookie', 'load_cookie']).describe('Action to perform'),
        data: z.record(z.any()).optional().describe('Data for the action')
      },
      async ({ action, data = {} }) => {
        try {
          switch (action) {
            case 'save':
              // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
              this.pb.authStore.save(data.token, data.record);
              return {
                content: [{ type: 'text', text: JSON.stringify({ success: true }, null, 2) }]
              };
            case 'clear':
              // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
              this.pb.authStore.clear();
              return {
                content: [{ type: 'text', text: JSON.stringify({ success: true }, null, 2) }]
              };
            case 'export_cookie':
              // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
              return {
                content: [{ type: 'text', text: this.pb.authStore.exportToCookie(data) }]
              };
            case 'load_cookie':
              // @ts-ignore - PocketBase has this method but TypeScript doesn't know about it
              this.pb.authStore.loadFromCookie(data.cookie);
              return {
                content: [{ type: 'text', text: JSON.stringify({ success: true }, null, 2) }]
              };
          }
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Failed to manage auth store: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Real-time subscription tool (Note: Streams data to server console, not back via MCP response)
    this.server.tool(
      'subscribe_to_collection',
      {
        collection: z.string().describe('Collection name to subscribe to'),
        recordId: z.string().optional().describe('Specific record ID to subscribe to (optional)'),
        filter: z.string().optional().describe('Filter expression for subscription (optional)')
        // How to handle the callback/stream is tricky with MCP's request/response model.
        // This implementation will log events to the server console.
      },
      async ({ collection, recordId, filter }) => {
        try {
          const subscribePath = recordId ? `${collection}/${recordId}` : collection;
          console.error(`[MCP PocketBase] Subscribing to ${subscribePath}...`);

          // The subscribe function takes a callback. We can't easily stream this back via MCP.
          // We'll log events to the server's console instead.
          // Also, managing unsubscription isn't straightforward in this model.
          // Cast to 'any' to bypass TS error if the specific type isn't correctly inferred
          await (this.pb.collection(collection) as any).subscribe(recordId || '*', (e: SubscriptionEvent) => {
            console.error(`[MCP PocketBase Subscription Event - ${collection}/${recordId || '*'}] Action: ${e.action}, Record:`, JSON.stringify(e.record, null, 2));
          }, { filter }); // Pass filter option if provided

          return {
            content: [{ type: 'text', text: `Successfully initiated subscription to collection '${collection}'${recordId ? ` for record '${recordId}'` : ''}. Events will be logged to the server console.` }]
          };
        } catch (error: any) {
          console.error(`[MCP PocketBase] Subscription failed for ${collection}/${recordId || '*'}:`, error);
          return {
            content: [{ type: 'text', text: `Failed to subscribe to collection: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Batch update tool
    this.server.tool(
      'batch_update_records',
      {
        collection: z.string().describe('Collection name'),
        records: z.array(z.object({
          id: z.string().describe('Record ID to update'),
          data: z.record(z.any()).describe('Data to update')
        })).describe('Array of records to update')
      },
      async ({ collection, records }) => {
        const results: any[] = [];
        const errors: any[] = [];
        try {
          for (const record of records) {
            try {
              const result = await this.pb.collection(collection).update(record.id, record.data);
              results.push({ id: record.id, status: 'success', result });
            } catch (error: any) {
              errors.push({ id: record.id, status: 'error', message: error.message });
            }
          }

          if (errors.length > 0) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ updated: results, errors: errors }, null, 2) }],
              isError: true // Indicate partial or full failure
            };
          }

          return {
            content: [{ type: 'text', text: JSON.stringify({ updated: results }, null, 2) }]
          };
        } catch (error: any) {
          // Catch potential errors outside the loop (though less likely here)
          return {
            content: [{ type: 'text', text: `Failed during batch update: ${error.message}` }],
            isError: true
          };
        }
      }
    );

    // Batch delete tool
    this.server.tool(
      'batch_delete_records',
      {
        collection: z.string().describe('Collection name'),
        recordIds: z.array(z.string()).describe('Array of Record IDs to delete')
      },
      async ({ collection, recordIds }) => {
        const results: any[] = [];
        const errors: any[] = [];
        try {
          for (const id of recordIds) {
            try {
              await this.pb.collection(collection).delete(id);
              results.push({ id: id, status: 'success' });
            } catch (error: any) {
              errors.push({ id: id, status: 'error', message: error.message });
            }
          }

          if (errors.length > 0) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ deleted: results, errors: errors }, null, 2) }],
              isError: true // Indicate partial or full failure
            };
          }

          return {
            content: [{ type: 'text', text: JSON.stringify({ deleted: results }, null, 2) }]
          };
        } catch (error: any) {
          // Catch potential errors outside the loop
          return {
            content: [{ type: 'text', text: `Failed during batch delete: ${error.message}` }],
            isError: true
          };
        }
      }
    );
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('PocketBase MCP server running on stdio');
  }
}

const server = new PocketBaseServer();
server.run().catch(console.error);

