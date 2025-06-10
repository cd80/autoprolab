import { 
  Agent, InsertAgent, 
  Team, InsertTeam,
  Target, InsertTarget,
  McpServer, InsertMcpServer,
  CustomTool, InsertCustomTool,
  HtbLab, InsertHtbLab,
  Activity, InsertActivity,
  NetworkNode, NetworkLink,
  agents, teams, targets, mcpServers, customTools, htbLabs, activities
} from "@shared/schema";
import { db } from "./db";
import { eq } from "drizzle-orm";

export interface IStorage {
  // Agents
  getAgents(): Promise<Agent[]>;
  getAgent(id: number): Promise<Agent | undefined>;
  createAgent(agent: InsertAgent): Promise<Agent>;
  updateAgent(id: number, agent: Partial<InsertAgent>): Promise<Agent | undefined>;
  deleteAgent(id: number): Promise<boolean>;

  // Teams
  getTeams(): Promise<Team[]>;
  getTeam(id: number): Promise<Team | undefined>;
  createTeam(team: InsertTeam): Promise<Team>;
  updateTeam(id: number, team: Partial<InsertTeam>): Promise<Team | undefined>;
  deleteTeam(id: number): Promise<boolean>;
  getTeamHierarchy(): Promise<Team[]>;

  // Targets
  getTargets(): Promise<Target[]>;
  getTarget(id: number): Promise<Target | undefined>;
  createTarget(target: InsertTarget): Promise<Target>;
  updateTarget(id: number, target: Partial<InsertTarget>): Promise<Target | undefined>;
  deleteTarget(id: number): Promise<boolean>;

  // MCP Servers
  getMcpServers(): Promise<McpServer[]>;
  getMcpServer(id: number): Promise<McpServer | undefined>;
  createMcpServer(server: InsertMcpServer): Promise<McpServer>;
  updateMcpServer(id: number, server: Partial<InsertMcpServer>): Promise<McpServer | undefined>;
  deleteMcpServer(id: number): Promise<boolean>;

  // Custom Tools
  getCustomTools(): Promise<CustomTool[]>;
  getCustomTool(id: number): Promise<CustomTool | undefined>;
  createCustomTool(tool: InsertCustomTool): Promise<CustomTool>;
  updateCustomTool(id: number, tool: Partial<InsertCustomTool>): Promise<CustomTool | undefined>;
  deleteCustomTool(id: number): Promise<boolean>;

  // HTB Labs
  getHtbLabs(): Promise<HtbLab[]>;
  getActiveHtbLab(): Promise<HtbLab | undefined>;
  createHtbLab(lab: InsertHtbLab): Promise<HtbLab>;
  updateHtbLab(id: number, lab: Partial<InsertHtbLab>): Promise<HtbLab | undefined>;

  // Activities
  getActivities(): Promise<Activity[]>;
  getRecentActivities(limit?: number): Promise<Activity[]>;
  createActivity(activity: InsertActivity): Promise<Activity>;

  // Network Topology
  getNetworkTopology(): Promise<{ nodes: NetworkNode[], links: NetworkLink[] }>;
  updateNetworkTopology(nodes: NetworkNode[], links: NetworkLink[]): Promise<void>;
}

export class MemStorage implements IStorage {
  private agents: Map<number, Agent> = new Map();
  private teams: Map<number, Team> = new Map();
  private targets: Map<number, Target> = new Map();
  private mcpServers: Map<number, McpServer> = new Map();
  private customTools: Map<number, CustomTool> = new Map();
  private htbLabs: Map<number, HtbLab> = new Map();
  private activities: Map<number, Activity> = new Map();
  private networkTopology: { nodes: NetworkNode[], links: NetworkLink[] } = { nodes: [], links: [] };

  private agentId = 1;
  private teamId = 1;
  private targetId = 1;
  private mcpServerId = 1;
  private customToolId = 1;
  private htbLabId = 1;
  private activityId = 1;

  constructor() {
    this.initializeDefaultData();
  }

  private initializeDefaultData() {
    // Initialize some default teams
    const redTeamAlpha: Team = {
      id: this.teamId++,
      name: "Red Team Alpha",
      description: "Primary red team for offensive operations",
      parentTeamId: null,
      createdAt: new Date(),
    };
    this.teams.set(redTeamAlpha.id, redTeamAlpha);

    const persistenceTeam: Team = {
      id: this.teamId++,
      name: "Persistence Team",
      description: "Specialized in maintaining access",
      parentTeamId: redTeamAlpha.id,
      createdAt: new Date(),
    };
    this.teams.set(persistenceTeam.id, persistenceTeam);

    // Initialize some default targets
    const dc01: Target = {
      id: this.targetId++,
      hostname: "DC01.corp.local",
      ipAddress: "192.168.1.10",
      operatingSystem: "Windows Server 2019",
      status: "compromised",
      openPorts: [
        { port: 22, service: "SSH" },
        { port: 80, service: "HTTP" },
        { port: 445, service: "SMB" }
      ],
      vulnerabilities: ["CVE-2021-34527"],
      flags: [
        { id: "user-flag-dc01", type: "user", status: "captured", capturedAt: new Date(Date.now() - 7200000).toISOString() },
        { id: "root-flag-dc01", type: "root", status: "captured", capturedAt: new Date(Date.now() - 3600000).toISOString() }
      ],
      networkSegment: "corp.local",
      assignedAgentId: null,
      createdAt: new Date(),
    };
    this.targets.set(dc01.id, dc01);

    const web01: Target = {
      id: this.targetId++,
      hostname: "WEB01.dmz.local",
      ipAddress: "10.10.10.50",
      operatingSystem: "Ubuntu 20.04",
      status: "in-progress",
      openPorts: [
        { port: 22, service: "SSH" },
        { port: 80, service: "HTTP" },
        { port: 443, service: "HTTPS" }
      ],
      vulnerabilities: ["SQL Injection"],
      flags: [
        { id: "user-flag-web01", type: "user", status: "captured", capturedAt: new Date(Date.now() - 1800000).toISOString() },
        { id: "root-flag-web01", type: "root", status: "pending" }
      ],
      networkSegment: "dmz.local",
      assignedAgentId: null,
      createdAt: new Date(),
    };
    this.targets.set(web01.id, web01);

    const db01: Target = {
      id: this.targetId++,
      hostname: "DB01.internal.local",
      ipAddress: "172.16.1.100",
      operatingSystem: "MSSQL 2017",
      status: "target",
      openPorts: [
        { port: 1433, service: "MSSQL" },
        { port: 3389, service: "RDP" }
      ],
      vulnerabilities: [],
      flags: [
        { id: "user-flag-db01", type: "user", status: "pending" },
        { id: "root-flag-db01", type: "root", status: "pending" }
      ],
      networkSegment: "internal.local",
      assignedAgentId: null,
      createdAt: new Date(),
    };
    this.targets.set(db01.id, db01);

    // Initialize HTB Lab
    const offshoreLab: HtbLab = {
      id: this.htbLabId++,
      name: "Offshore",
      status: "active",
      totalFlags: 16,
      capturedFlags: 11,
      completionPercentage: 68.75,
      startedAt: new Date(Date.now() - 86400000 * 3), // 3 days ago
      completedAt: null,
    };
    this.htbLabs.set(offshoreLab.id, offshoreLab);

    // Initialize MCP Servers
    const nmapServer: McpServer = {
      id: this.mcpServerId++,
      name: "Nmap Scanner",
      url: "mcp://nmap-server:8080",
      status: "online",
      tools: ["nmap", "masscan", "ncat"],
      createdAt: new Date(),
    };
    this.mcpServers.set(nmapServer.id, nmapServer);

    const msfServer: McpServer = {
      id: this.mcpServerId++,
      name: "Metasploit Server",
      url: "mcp://msf-server:4444",
      status: "online",
      tools: ["msfconsole", "msfvenom", "exploit"],
      createdAt: new Date(),
    };
    this.mcpServers.set(msfServer.id, msfServer);

    // Initialize network topology
    this.networkTopology = {
      nodes: [
        { id: 'attacker', name: 'Attacker', type: 'attacker', x: 100, y: 200 },
        { id: 'router', name: 'Router', type: 'infrastructure', x: 250, y: 200 },
        { id: 'dc01', name: 'DC01', type: 'compromised', x: 400, y: 150, targetId: dc01.id },
        { id: 'web01', name: 'WEB01', type: 'in-progress', x: 400, y: 200, targetId: web01.id },
        { id: 'db01', name: 'DB01', type: 'target', x: 550, y: 250, targetId: db01.id },
        { id: 'internal-router', name: 'Internal Router', type: 'infrastructure', x: 400, y: 350 }
      ],
      links: [
        { source: 'attacker', target: 'router' },
        { source: 'router', target: 'dc01' },
        { source: 'router', target: 'web01' },
        { source: 'web01', target: 'internal-router' },
        { source: 'internal-router', target: 'db01' }
      ]
    };
  }

  // Agents
  async getAgents(): Promise<Agent[]> {
    return Array.from(this.agents.values());
  }

  async getAgent(id: number): Promise<Agent | undefined> {
    return this.agents.get(id);
  }

  async createAgent(insertAgent: InsertAgent): Promise<Agent> {
    const agent: Agent = {
      ...insertAgent,
      id: this.agentId++,
      tools: insertAgent.tools || [],
      status: insertAgent.status || "inactive",
      teamId: insertAgent.teamId || null,
      createdAt: new Date(),
    };
    this.agents.set(agent.id, agent);
    return agent;
  }

  async updateAgent(id: number, agent: Partial<InsertAgent>): Promise<Agent | undefined> {
    const existing = this.agents.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...agent };
    this.agents.set(id, updated);
    return updated;
  }

  async deleteAgent(id: number): Promise<boolean> {
    return this.agents.delete(id);
  }

  // Teams
  async getTeams(): Promise<Team[]> {
    return Array.from(this.teams.values());
  }

  async getTeam(id: number): Promise<Team | undefined> {
    return this.teams.get(id);
  }

  async createTeam(insertTeam: InsertTeam): Promise<Team> {
    const team: Team = {
      ...insertTeam,
      id: this.teamId++,
      description: insertTeam.description || null,
      parentTeamId: insertTeam.parentTeamId || null,
      createdAt: new Date(),
    };
    this.teams.set(team.id, team);
    return team;
  }

  async updateTeam(id: number, team: Partial<InsertTeam>): Promise<Team | undefined> {
    const existing = this.teams.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...team };
    this.teams.set(id, updated);
    return updated;
  }

  async deleteTeam(id: number): Promise<boolean> {
    return this.teams.delete(id);
  }

  async getTeamHierarchy(): Promise<Team[]> {
    return Array.from(this.teams.values());
  }

  // Targets
  async getTargets(): Promise<Target[]> {
    return Array.from(this.targets.values());
  }

  async getTarget(id: number): Promise<Target | undefined> {
    return this.targets.get(id);
  }

  async createTarget(insertTarget: InsertTarget): Promise<Target> {
    const target: Target = {
      ...insertTarget,
      id: this.targetId++,
      status: insertTarget.status || "target",
      operatingSystem: insertTarget.operatingSystem || null,
      openPorts: insertTarget.openPorts || [],
      vulnerabilities: insertTarget.vulnerabilities || [],
      flags: insertTarget.flags || [],
      networkSegment: insertTarget.networkSegment || null,
      assignedAgentId: insertTarget.assignedAgentId || null,
      createdAt: new Date(),
    };
    this.targets.set(target.id, target);
    return target;
  }

  async updateTarget(id: number, target: Partial<InsertTarget>): Promise<Target | undefined> {
    const existing = this.targets.get(id);
    if (!existing) return undefined;
    
    const updated: Target = { 
      ...existing, 
      ...target,
    };
    this.targets.set(id, updated);
    return updated;
  }

  async deleteTarget(id: number): Promise<boolean> {
    return this.targets.delete(id);
  }

  // MCP Servers
  async getMcpServers(): Promise<McpServer[]> {
    return Array.from(this.mcpServers.values());
  }

  async getMcpServer(id: number): Promise<McpServer | undefined> {
    return this.mcpServers.get(id);
  }

  async createMcpServer(insertServer: InsertMcpServer): Promise<McpServer> {
    const server: McpServer = {
      ...insertServer,
      id: this.mcpServerId++,
      tools: insertServer.tools || null,
      status: insertServer.status || "offline",
      createdAt: new Date(),
    };
    this.mcpServers.set(server.id, server);
    return server;
  }

  async updateMcpServer(id: number, server: Partial<InsertMcpServer>): Promise<McpServer | undefined> {
    const existing = this.mcpServers.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...server };
    this.mcpServers.set(id, updated);
    return updated;
  }

  async deleteMcpServer(id: number): Promise<boolean> {
    return this.mcpServers.delete(id);
  }

  // Custom Tools
  async getCustomTools(): Promise<CustomTool[]> {
    return Array.from(this.customTools.values());
  }

  async getCustomTool(id: number): Promise<CustomTool | undefined> {
    return this.customTools.get(id);
  }

  async createCustomTool(insertTool: InsertCustomTool): Promise<CustomTool> {
    const tool: CustomTool = {
      ...insertTool,
      id: this.customToolId++,
      status: insertTool.status || "active",
      code: insertTool.code || null,
      createdAt: new Date(),
    };
    this.customTools.set(tool.id, tool);
    return tool;
  }

  async updateCustomTool(id: number, tool: Partial<InsertCustomTool>): Promise<CustomTool | undefined> {
    const existing = this.customTools.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...tool };
    this.customTools.set(id, updated);
    return updated;
  }

  async deleteCustomTool(id: number): Promise<boolean> {
    return this.customTools.delete(id);
  }

  // HTB Labs
  async getHtbLabs(): Promise<HtbLab[]> {
    return Array.from(this.htbLabs.values());
  }

  async getActiveHtbLab(): Promise<HtbLab | undefined> {
    return Array.from(this.htbLabs.values()).find(lab => lab.status === "active");
  }

  async createHtbLab(insertLab: InsertHtbLab): Promise<HtbLab> {
    const lab: HtbLab = {
      ...insertLab,
      id: this.htbLabId++,
      status: insertLab.status || "inactive",
      totalFlags: insertLab.totalFlags || 0,
      capturedFlags: insertLab.capturedFlags || 0,
      completionPercentage: insertLab.completionPercentage || 0,
      startedAt: insertLab.startedAt || null,
      completedAt: insertLab.completedAt || null,
    };
    this.htbLabs.set(lab.id, lab);
    return lab;
  }

  async updateHtbLab(id: number, lab: Partial<InsertHtbLab>): Promise<HtbLab | undefined> {
    const existing = this.htbLabs.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...lab };
    this.htbLabs.set(id, updated);
    return updated;
  }

  // Activities
  async getActivities(): Promise<Activity[]> {
    return Array.from(this.activities.values()).sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  async getRecentActivities(limit: number = 10): Promise<Activity[]> {
    const activities = await this.getActivities();
    return activities.slice(0, limit);
  }

  async createActivity(insertActivity: InsertActivity): Promise<Activity> {
    const activity: Activity = {
      ...insertActivity,
      id: this.activityId++,
      status: insertActivity.status || "in-progress",
      agentId: insertActivity.agentId || null,
      targetId: insertActivity.targetId || null,
      result: insertActivity.result || null,
      createdAt: new Date(),
    };
    this.activities.set(activity.id, activity);
    return activity;
  }

  // Network Topology
  async getNetworkTopology(): Promise<{ nodes: NetworkNode[], links: NetworkLink[] }> {
    return this.networkTopology;
  }

  async updateNetworkTopology(nodes: NetworkNode[], links: NetworkLink[]): Promise<void> {
    this.networkTopology = { nodes, links };
  }
}

export class DatabaseStorage implements IStorage {
  // Agents
  async getAgents(): Promise<Agent[]> {
    return await db.select().from(agents);
  }

  async getAgent(id: number): Promise<Agent | undefined> {
    const [agent] = await db.select().from(agents).where(eq(agents.id, id));
    return agent || undefined;
  }

  async createAgent(insertAgent: InsertAgent): Promise<Agent> {
    const [agent] = await db
      .insert(agents)
      .values(insertAgent)
      .returning();
    return agent;
  }

  async updateAgent(id: number, agent: Partial<InsertAgent>): Promise<Agent | undefined> {
    const [updated] = await db
      .update(agents)
      .set(agent)
      .where(eq(agents.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteAgent(id: number): Promise<boolean> {
    const result = await db.delete(agents).where(eq(agents.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  // Teams
  async getTeams(): Promise<Team[]> {
    return await db.select().from(teams);
  }

  async getTeam(id: number): Promise<Team | undefined> {
    const [team] = await db.select().from(teams).where(eq(teams.id, id));
    return team || undefined;
  }

  async createTeam(insertTeam: InsertTeam): Promise<Team> {
    const [team] = await db
      .insert(teams)
      .values(insertTeam)
      .returning();
    return team;
  }

  async updateTeam(id: number, team: Partial<InsertTeam>): Promise<Team | undefined> {
    const [updated] = await db
      .update(teams)
      .set(team)
      .where(eq(teams.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteTeam(id: number): Promise<boolean> {
    const result = await db.delete(teams).where(eq(teams.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getTeamHierarchy(): Promise<Team[]> {
    return await db.select().from(teams);
  }

  // Targets
  async getTargets(): Promise<Target[]> {
    return await db.select().from(targets);
  }

  async getTarget(id: number): Promise<Target | undefined> {
    const [target] = await db.select().from(targets).where(eq(targets.id, id));
    return target || undefined;
  }

  async createTarget(insertTarget: InsertTarget): Promise<Target> {
    const [target] = await db
      .insert(targets)
      .values(insertTarget)
      .returning();
    return target;
  }

  async updateTarget(id: number, target: Partial<InsertTarget>): Promise<Target | undefined> {
    const updateData = {
      ...target,
      openPorts: target.openPorts ? (Array.isArray(target.openPorts) ? target.openPorts : []) : undefined,
      vulnerabilities: target.vulnerabilities ? (Array.isArray(target.vulnerabilities) ? target.vulnerabilities : []) : undefined,
      flags: target.flags ? (Array.isArray(target.flags) ? target.flags : []) : undefined
    };
    
    Object.keys(updateData).forEach(key => {
      if (updateData[key as keyof typeof updateData] === undefined) {
        delete updateData[key as keyof typeof updateData];
      }
    });
    
    const [updated] = await db
      .update(targets)
      .set(updateData)
      .where(eq(targets.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteTarget(id: number): Promise<boolean> {
    const result = await db.delete(targets).where(eq(targets.id, id));
    return (result.rowCount || 0) > 0;
  }

  // MCP Servers
  async getMcpServers(): Promise<McpServer[]> {
    return await db.select().from(mcpServers);
  }

  async getMcpServer(id: number): Promise<McpServer | undefined> {
    const [server] = await db.select().from(mcpServers).where(eq(mcpServers.id, id));
    return server || undefined;
  }

  async createMcpServer(insertServer: InsertMcpServer): Promise<McpServer> {
    const [server] = await db
      .insert(mcpServers)
      .values(insertServer)
      .returning();
    return server;
  }

  async updateMcpServer(id: number, server: Partial<InsertMcpServer>): Promise<McpServer | undefined> {
    const [updated] = await db
      .update(mcpServers)
      .set(server)
      .where(eq(mcpServers.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteMcpServer(id: number): Promise<boolean> {
    const result = await db.delete(mcpServers).where(eq(mcpServers.id, id));
    return (result.rowCount || 0) > 0;
  }

  // Custom Tools
  async getCustomTools(): Promise<CustomTool[]> {
    return await db.select().from(customTools);
  }

  async getCustomTool(id: number): Promise<CustomTool | undefined> {
    const [tool] = await db.select().from(customTools).where(eq(customTools.id, id));
    return tool || undefined;
  }

  async createCustomTool(insertTool: InsertCustomTool): Promise<CustomTool> {
    const [tool] = await db
      .insert(customTools)
      .values(insertTool)
      .returning();
    return tool;
  }

  async updateCustomTool(id: number, tool: Partial<InsertCustomTool>): Promise<CustomTool | undefined> {
    const [updated] = await db
      .update(customTools)
      .set(tool)
      .where(eq(customTools.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteCustomTool(id: number): Promise<boolean> {
    const result = await db.delete(customTools).where(eq(customTools.id, id));
    return (result.rowCount || 0) > 0;
  }

  // HTB Labs
  async getHtbLabs(): Promise<HtbLab[]> {
    return await db.select().from(htbLabs);
  }

  async getActiveHtbLab(): Promise<HtbLab | undefined> {
    const [lab] = await db.select().from(htbLabs).where(eq(htbLabs.status, "active"));
    return lab || undefined;
  }

  async createHtbLab(insertLab: InsertHtbLab): Promise<HtbLab> {
    const [lab] = await db
      .insert(htbLabs)
      .values(insertLab)
      .returning();
    return lab;
  }

  async updateHtbLab(id: number, lab: Partial<InsertHtbLab>): Promise<HtbLab | undefined> {
    const [updated] = await db
      .update(htbLabs)
      .set(lab)
      .where(eq(htbLabs.id, id))
      .returning();
    return updated || undefined;
  }

  // Activities
  async getActivities(): Promise<Activity[]> {
    return await db.select().from(activities);
  }

  async getRecentActivities(limit: number = 10): Promise<Activity[]> {
    return await db.select().from(activities).limit(limit);
  }

  async createActivity(insertActivity: InsertActivity): Promise<Activity> {
    const [activity] = await db
      .insert(activities)
      .values(insertActivity)
      .returning();
    return activity;
  }

  // Network Topology (stored in memory for now)
  private networkTopology: { nodes: NetworkNode[], links: NetworkLink[] } = { nodes: [], links: [] };

  async getNetworkTopology(): Promise<{ nodes: NetworkNode[], links: NetworkLink[] }> {
    return this.networkTopology;
  }

  async updateNetworkTopology(nodes: NetworkNode[], links: NetworkLink[]): Promise<void> {
    this.networkTopology = { nodes, links };
  }
}

export const storage = new DatabaseStorage();
