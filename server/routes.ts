import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  insertAgentSchema, insertTeamSchema, insertTargetSchema, 
  insertMcpServerSchema, insertCustomToolSchema, insertHtbLabSchema,
  insertActivitySchema 
} from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  
  // Agents routes
  app.get("/api/agents", async (req, res) => {
    try {
      const agents = await storage.getAgents();
      res.json(agents);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch agents" });
    }
  });

  app.get("/api/agents/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const agent = await storage.getAgent(id);
      if (!agent) {
        return res.status(404).json({ message: "Agent not found" });
      }
      res.json(agent);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch agent" });
    }
  });

  app.post("/api/agents", async (req, res) => {
    try {
      const agentData = insertAgentSchema.parse(req.body);
      const agent = await storage.createAgent(agentData);
      res.status(201).json(agent);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid agent data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create agent" });
    }
  });

  app.put("/api/agents/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const agentData = insertAgentSchema.partial().parse(req.body);
      const agent = await storage.updateAgent(id, agentData);
      if (!agent) {
        return res.status(404).json({ message: "Agent not found" });
      }
      res.json(agent);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid agent data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update agent" });
    }
  });

  app.delete("/api/agents/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const success = await storage.deleteAgent(id);
      if (!success) {
        return res.status(404).json({ message: "Agent not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete agent" });
    }
  });

  // Teams routes
  app.get("/api/teams", async (req, res) => {
    try {
      const teams = await storage.getTeams();
      res.json(teams);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch teams" });
    }
  });

  app.get("/api/teams/hierarchy", async (req, res) => {
    try {
      const teams = await storage.getTeamHierarchy();
      res.json(teams);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch team hierarchy" });
    }
  });

  app.post("/api/teams", async (req, res) => {
    try {
      const teamData = insertTeamSchema.parse(req.body);
      const team = await storage.createTeam(teamData);
      res.status(201).json(team);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid team data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create team" });
    }
  });

  app.put("/api/teams/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const teamData = insertTeamSchema.partial().parse(req.body);
      const team = await storage.updateTeam(id, teamData);
      if (!team) {
        return res.status(404).json({ message: "Team not found" });
      }
      res.json(team);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid team data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update team" });
    }
  });

  app.delete("/api/teams/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const success = await storage.deleteTeam(id);
      if (!success) {
        return res.status(404).json({ message: "Team not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete team" });
    }
  });

  // Targets routes
  app.get("/api/targets", async (req, res) => {
    try {
      const targets = await storage.getTargets();
      res.json(targets);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch targets" });
    }
  });

  app.get("/api/targets/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const target = await storage.getTarget(id);
      if (!target) {
        return res.status(404).json({ message: "Target not found" });
      }
      res.json(target);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch target" });
    }
  });

  app.post("/api/targets", async (req, res) => {
    try {
      const targetData = insertTargetSchema.parse(req.body);
      const target = await storage.createTarget(targetData);
      res.status(201).json(target);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid target data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create target" });
    }
  });

  app.put("/api/targets/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const targetData = insertTargetSchema.partial().parse(req.body);
      const target = await storage.updateTarget(id, targetData);
      if (!target) {
        return res.status(404).json({ message: "Target not found" });
      }
      res.json(target);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid target data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update target" });
    }
  });

  app.delete("/api/targets/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const success = await storage.deleteTarget(id);
      if (!success) {
        return res.status(404).json({ message: "Target not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete target" });
    }
  });

  // Target actions
  app.post("/api/targets/:id/actions/:action", async (req, res) => {
    try {
      const targetId = parseInt(req.params.id);
      const action = req.params.action;
      const { agentId } = req.body;

      const target = await storage.getTarget(targetId);
      if (!target) {
        return res.status(404).json({ message: "Target not found" });
      }

      // Create activity record
      const activity = await storage.createActivity({
        agentId: agentId || null,
        targetId,
        action,
        description: `${action} initiated against ${target.hostname}`,
        status: "in-progress",
        result: null,
      });

      res.json({ message: `${action} started`, activity });
    } catch (error) {
      res.status(500).json({ message: `Failed to start ${req.params.action}` });
    }
  });

  // MCP Servers routes
  app.get("/api/mcp-servers", async (req, res) => {
    try {
      const servers = await storage.getMcpServers();
      res.json(servers);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch MCP servers" });
    }
  });

  app.post("/api/mcp-servers", async (req, res) => {
    try {
      const serverData = insertMcpServerSchema.parse(req.body);
      const server = await storage.createMcpServer(serverData);
      res.status(201).json(server);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid MCP server data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create MCP server" });
    }
  });

  app.put("/api/mcp-servers/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const serverData = insertMcpServerSchema.partial().parse(req.body);
      const server = await storage.updateMcpServer(id, serverData);
      if (!server) {
        return res.status(404).json({ message: "MCP server not found" });
      }
      res.json(server);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid MCP server data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update MCP server" });
    }
  });

  app.delete("/api/mcp-servers/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const success = await storage.deleteMcpServer(id);
      if (!success) {
        return res.status(404).json({ message: "MCP server not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete MCP server" });
    }
  });

  // Custom Tools routes
  app.get("/api/custom-tools", async (req, res) => {
    try {
      const tools = await storage.getCustomTools();
      res.json(tools);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch custom tools" });
    }
  });

  app.post("/api/custom-tools", async (req, res) => {
    try {
      const toolData = insertCustomToolSchema.parse(req.body);
      const tool = await storage.createCustomTool(toolData);
      res.status(201).json(tool);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid custom tool data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create custom tool" });
    }
  });

  app.put("/api/custom-tools/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const toolData = insertCustomToolSchema.partial().parse(req.body);
      const tool = await storage.updateCustomTool(id, toolData);
      if (!tool) {
        return res.status(404).json({ message: "Custom tool not found" });
      }
      res.json(tool);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid custom tool data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update custom tool" });
    }
  });

  app.delete("/api/custom-tools/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const success = await storage.deleteCustomTool(id);
      if (!success) {
        return res.status(404).json({ message: "Custom tool not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete custom tool" });
    }
  });

  // HTB Labs routes
  app.get("/api/htb-labs", async (req, res) => {
    try {
      const labs = await storage.getHtbLabs();
      res.json(labs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch HTB labs" });
    }
  });

  app.get("/api/htb-labs/active", async (req, res) => {
    try {
      const lab = await storage.getActiveHtbLab();
      if (!lab) {
        return res.status(404).json({ message: "No active HTB lab found" });
      }
      res.json(lab);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch active HTB lab" });
    }
  });

  app.post("/api/htb-labs", async (req, res) => {
    try {
      const labData = insertHtbLabSchema.parse(req.body);
      const lab = await storage.createHtbLab(labData);
      res.status(201).json(lab);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid HTB lab data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create HTB lab" });
    }
  });

  app.put("/api/htb-labs/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const labData = insertHtbLabSchema.partial().parse(req.body);
      const lab = await storage.updateHtbLab(id, labData);
      if (!lab) {
        return res.status(404).json({ message: "HTB lab not found" });
      }
      res.json(lab);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid HTB lab data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update HTB lab" });
    }
  });

  // Activities routes
  app.get("/api/activities", async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const activities = limit 
        ? await storage.getRecentActivities(limit)
        : await storage.getActivities();
      res.json(activities);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch activities" });
    }
  });

  app.post("/api/activities", async (req, res) => {
    try {
      const activityData = insertActivitySchema.parse(req.body);
      const activity = await storage.createActivity(activityData);
      res.status(201).json(activity);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid activity data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create activity" });
    }
  });

  // Network topology routes
  app.get("/api/network-topology", async (req, res) => {
    try {
      const topology = await storage.getNetworkTopology();
      res.json(topology);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch network topology" });
    }
  });

  app.put("/api/network-topology", async (req, res) => {
    try {
      const { nodes, links } = req.body;
      await storage.updateNetworkTopology(nodes, links);
      res.json({ message: "Network topology updated" });
    } catch (error) {
      res.status(500).json({ message: "Failed to update network topology" });
    }
  });

  // Dashboard metrics
  app.get("/api/dashboard/metrics", async (req, res) => {
    try {
      const agents = await storage.getAgents();
      const targets = await storage.getTargets();
      const activeHtbLab = await storage.getActiveHtbLab();
      const mcpServers = await storage.getMcpServers();

      const metrics = {
        activeAgents: agents.filter(a => a.status === "active").length,
        compromisedHosts: targets.filter(t => t.status === "compromised").length,
        flagsCaptured: activeHtbLab ? `${activeHtbLab.capturedFlags}/${activeHtbLab.totalFlags}` : "0/0",
        mcpTools: mcpServers.reduce((total, server) => total + server.tools.length, 0),
        targetCount: targets.length,
        labProgress: activeHtbLab ? `${activeHtbLab.completionPercentage}%` : "0%"
      };

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dashboard metrics" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
