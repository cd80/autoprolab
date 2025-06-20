import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { htbOperator } from "./htb-integration";
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
        mcpTools: mcpServers.reduce((total, server) => total + (server.tools?.length || 0), 0),
        targetCount: targets.length,
        labProgress: activeHtbLab ? `${activeHtbLab.completionPercentage}%` : "0%"
      };

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dashboard metrics" });
    }
  });

  // HTB Operator Integration
  app.get("/api/htb-operator/labs", async (req, res) => {
    try {
      const htbLabs = await htbOperator.getAvailableLabs();
      
      const proLabs = htbLabs.map(lab => ({
        id: lab.id,
        name: lab.name,
        difficulty: lab.difficulty,
        machines: lab.machines.length,
        flags: 0,
        description: lab.description,
        estimatedTime: lab.difficulty === "Expert" ? "60-80 hours" : 
                      lab.difficulty === "Hard" ? "40-60 hours" : "30-40 hours",
        userProgress: {
          capturedFlags: 0,
          completionPercentage: 0,
          isActive: lab.status === 'active'
        }
      }));

      res.json(proLabs);
    } catch (error) {
      console.error("Failed to fetch Pro Labs from htb-operator:", error);
      res.status(500).json({ error: "Failed to fetch Pro Labs from htb-operator" });
    }
  });

  app.post("/api/htb-operator/labs/:labId/start", async (req, res) => {
    try {
      const { labId } = req.params;
      
      console.log(`Starting HTB Pro Lab: ${labId}`);
      
      const result = await htbOperator.startLab(labId);
      
      if (result.success && result.lab) {
        // Create or update HTB lab record in storage
        const labData = {
          name: result.lab.name,
          status: "active" as const,
          capturedFlags: 0,
          totalFlags: 0,
          completionPercentage: 0,
          startedAt: new Date(),
        };

        const htbLab = await storage.createHtbLab(labData);
        
        res.json({
          success: true,
          message: result.message,
          lab: htbLab
        });
      } else {
        res.status(500).json({ 
          success: false,
          error: result.message || "Failed to start Pro Lab" 
        });
      }
    } catch (error) {
      console.error("Failed to start HTB lab:", error);
      res.status(500).json({ error: "Failed to start Pro Lab" });
    }
  });

  app.post("/api/htb-operator/labs/stop", async (req, res) => {
    try {
      console.log("Stopping active HTB Pro Lab");
      
      const result = await htbOperator.stopLab();
      
      if (result.success) {
        const activeLab = await storage.getActiveHtbLab();
        if (activeLab) {
          await storage.updateHtbLab(activeLab.id, { 
            status: "inactive" as const
          });
        }
        
        res.json({
          success: true,
          message: result.message
        });
      } else {
        res.status(500).json({ 
          success: false,
          error: result.message || "Failed to stop Pro Lab" 
        });
      }
    } catch (error) {
      console.error("Failed to stop HTB lab:", error);
      res.status(500).json({ error: "Failed to stop Pro Lab" });
    }
  });

  app.post("/api/agents/deploy-aptlabs", async (req, res) => {
    try {
      console.log("Deploying APTLabs agents...");
      
      const { spawn } = require('child_process');
      const pythonProcess = spawn('python', ['-c', `
import sys
import os
sys.path.append('${process.cwd()}/..')
from aptlabs_agent_config import AptlabsAgentDeployer
import asyncio

async def deploy():
    deployer = AptlabsAgentDeployer()
    result = await deployer.deploy_aptlabs_agents()
    print(f"DEPLOYMENT_RESULT:{result}")
    return result

if __name__ == "__main__":
    result = asyncio.run(deploy())
`], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data: Buffer) => {
        error += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code === 0) {
          const resultMatch = output.match(/DEPLOYMENT_RESULT:(.+)/);
          let deploymentResult = { success: true, agents_deployed: [] };
          
          if (resultMatch) {
            try {
              deploymentResult = JSON.parse(resultMatch[1].replace(/'/g, '"'));
            } catch (e) {
              console.log("Could not parse deployment result, using default");
            }
          }

          res.json({
            success: true,
            message: 'APTLabs agents deployed successfully',
            agents: deploymentResult.agents_deployed || [],
            deployment_details: deploymentResult
          });
        } else {
          console.error("APTLabs deployment failed:", error);
          res.status(500).json({
            success: false,
            error: error || 'Failed to deploy APTLabs agents'
          });
        }
      });

    } catch (error: any) {
      console.error("APTLabs deployment error:", error);
      res.status(500).json({
        success: false,
        error: error.message || 'Internal server error during APTLabs deployment'
      });
    }
  });

  app.post("/api/agents/capture-flags-aptlabs", async (req, res) => {
    try {
      console.log("Starting APTLabs flag capture operation...");
      
      const { spawn } = require('child_process');
      const pythonProcess = spawn('python', ['-c', `
import sys
import os
sys.path.append('${process.cwd()}/..')
from aptlabs_agent_config import AptlabsAgentDeployer
import asyncio

async def capture_flags():
    deployer = AptlabsAgentDeployer()
    result = await deployer.execute_flag_capture()
    print(f"FLAG_CAPTURE_RESULT:{result}")
    return result

if __name__ == "__main__":
    result = asyncio.run(capture_flags())
`], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data: Buffer) => {
        error += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code === 0) {
          const resultMatch = output.match(/FLAG_CAPTURE_RESULT:(.+)/);
          let captureResult = { success: true, flags_captured: 0 };
          
          if (resultMatch) {
            try {
              captureResult = JSON.parse(resultMatch[1].replace(/'/g, '"'));
            } catch (e) {
              console.log("Could not parse capture result, using default");
            }
          }

          res.json({
            success: true,
            message: 'APTLabs flag capture operation completed',
            results: captureResult
          });
        } else {
          console.error("APTLabs flag capture failed:", error);
          res.status(500).json({
            success: false,
            error: error || 'Failed to execute flag capture operation'
          });
        }
      });

    } catch (error: any) {
      console.error("APTLabs flag capture error:", error);
      res.status(500).json({
        success: false,
        error: error.message || 'Internal server error during flag capture'
      });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
