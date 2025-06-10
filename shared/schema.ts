import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const agents = pgTable("agents", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  type: text("type").notNull(), // recon, exploit, persistence, lateral, collection
  description: text("description").notNull(),
  instructions: text("instructions").notNull(),
  expectedOutput: text("expected_output").notNull(),
  tools: text("tools").array().notNull().default([]),
  teamId: integer("team_id"),
  status: text("status").notNull().default("inactive"), // active, inactive, busy
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const teams = pgTable("teams", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  parentTeamId: integer("parent_team_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const targets = pgTable("targets", {
  id: serial("id").primaryKey(),
  hostname: text("hostname").notNull(),
  ipAddress: text("ip_address").notNull(),
  operatingSystem: text("operating_system"),
  status: text("status").notNull().default("target"), // target, in-progress, compromised
  openPorts: jsonb("open_ports").$type<Array<{port: number, service: string}>>().default([]),
  vulnerabilities: text("vulnerabilities").array().default([]),
  flags: jsonb("flags").$type<Array<{id: string, type: string, status: string, capturedAt?: string}>>().default([]),
  networkSegment: text("network_segment"),
  assignedAgentId: integer("assigned_agent_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const mcpServers = pgTable("mcp_servers", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(),
  status: text("status").notNull().default("offline"), // online, offline, error
  tools: text("tools").array().default([]),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const customTools = pgTable("custom_tools", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  language: text("language").notNull(),
  version: text("version").notNull(),
  status: text("status").notNull().default("active"), // active, inactive
  code: text("code"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const htbLabs = pgTable("htb_labs", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  status: text("status").notNull().default("inactive"), // active, inactive, completed
  totalFlags: integer("total_flags").notNull().default(0),
  capturedFlags: integer("captured_flags").notNull().default(0),
  completionPercentage: integer("completion_percentage").notNull().default(0),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
});

export const activities = pgTable("activities", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id"),
  targetId: integer("target_id"),
  action: text("action").notNull(),
  description: text("description").notNull(),
  status: text("status").notNull().default("in-progress"), // completed, in-progress, failed
  result: text("result"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Insert schemas
export const insertAgentSchema = createInsertSchema(agents).omit({
  id: true,
  createdAt: true,
});

export const insertTeamSchema = createInsertSchema(teams).omit({
  id: true,
  createdAt: true,
});

export const insertTargetSchema = createInsertSchema(targets).omit({
  id: true,
  createdAt: true,
});

export const insertMcpServerSchema = createInsertSchema(mcpServers).omit({
  id: true,
  createdAt: true,
});

export const insertCustomToolSchema = createInsertSchema(customTools).omit({
  id: true,
  createdAt: true,
});

export const insertHtbLabSchema = createInsertSchema(htbLabs).omit({
  id: true,
});

export const insertActivitySchema = createInsertSchema(activities).omit({
  id: true,
  createdAt: true,
});

// Types
export type Agent = typeof agents.$inferSelect;
export type InsertAgent = z.infer<typeof insertAgentSchema>;

export type Team = typeof teams.$inferSelect;
export type InsertTeam = z.infer<typeof insertTeamSchema>;

export type Target = typeof targets.$inferSelect;
export type InsertTarget = z.infer<typeof insertTargetSchema>;

export type McpServer = typeof mcpServers.$inferSelect;
export type InsertMcpServer = z.infer<typeof insertMcpServerSchema>;

export type CustomTool = typeof customTools.$inferSelect;
export type InsertCustomTool = z.infer<typeof insertCustomToolSchema>;

export type HtbLab = typeof htbLabs.$inferSelect;
export type InsertHtbLab = z.infer<typeof insertHtbLabSchema>;

export type Activity = typeof activities.$inferSelect;
export type InsertActivity = z.infer<typeof insertActivitySchema>;

// Network topology types
export type NetworkNode = {
  id: string;
  name: string;
  type: 'attacker' | 'infrastructure' | 'compromised' | 'in-progress' | 'target';
  x?: number;
  y?: number;
  targetId?: number;
};

export type NetworkLink = {
  source: string;
  target: string;
};
