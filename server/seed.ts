import { db } from "./db";
import { teams, targets, htbLabs, mcpServers } from "@shared/schema";

export async function seedDatabase() {
  try {
    // Check if data already exists
    const existingTeams = await db.select().from(teams);
    if (existingTeams.length > 0) {
      console.log("Database already seeded, skipping...");
      return;
    }

    console.log("Seeding database with initial data...");

    // Insert teams
    await db.insert(teams).values([
      {
        name: "Red Team Alpha",
        description: "Primary offensive security team specializing in infrastructure penetration",
        parentTeamId: null
      },
      {
        name: "Persistence Team",
        description: "Specialized team focused on maintaining access and establishing persistence",
        parentTeamId: 1
      }
    ]);

    // Insert targets
    await db.insert(targets).values([
      {
        hostname: "DC01.corp.local",
        ipAddress: "192.168.1.10",
        status: "compromised",
        operatingSystem: "Windows Server 2019",
        openPorts: [
          { port: 53, service: "DNS" },
          { port: 88, service: "Kerberos" },
          { port: 135, service: "RPC" },
          { port: 389, service: "LDAP" },
          { port: 445, service: "SMB" },
          { port: 3389, service: "RDP" }
        ],
        flags: [
          { id: "user", type: "user", status: "captured", capturedAt: "2024-01-15T10:30:00Z" },
          { id: "root", type: "root", status: "captured", capturedAt: "2024-01-15T14:45:00Z" }
        ]
      },
      {
        hostname: "WEB01.dmz.local",
        ipAddress: "10.10.10.50",
        status: "in-progress",
        operatingSystem: "Ubuntu 20.04",
        openPorts: [
          { port: 22, service: "SSH" },
          { port: 80, service: "HTTP" },
          { port: 443, service: "HTTPS" }
        ],
        flags: [
          { id: "user", type: "user", status: "in-progress" }
        ]
      },
      {
        hostname: "DB01.internal.local",
        ipAddress: "172.16.1.100",
        status: "target",
        operatingSystem: "MSSQL 2017",
        openPorts: [
          { port: 1433, service: "MSSQL" },
          { port: 3389, service: "RDP" }
        ],
        flags: [
          { id: "user", type: "user", status: "not-captured" }
        ]
      }
    ]);

    // Insert HTB Lab
    await db.insert(htbLabs).values([
      {
        name: "Offshore",
        status: "active",
        capturedFlags: 2,
        totalFlags: 5,
        completionPercentage: 40,
        difficulty: "Hard",
        description: "Advanced Active Directory environment with multiple attack vectors"
      }
    ]);

    // Insert MCP Servers
    await db.insert(mcpServers).values([
      {
        name: "Nmap Scanner",
        url: "mcp://localhost:8001/nmap",
        status: "online",
        description: "Network discovery and security auditing",
        tools: ["host_discovery", "port_scan", "service_detection", "os_detection", "vulnerability_scan"]
      },
      {
        name: "Metasploit Framework",
        url: "mcp://localhost:8002/msf",
        status: "online", 
        description: "Penetration testing framework",
        tools: ["exploit_search", "payload_generation", "session_management", "post_exploitation"]
      }
    ]);

    console.log("Database seeded successfully!");
  } catch (error) {
    console.error("Error seeding database:", error);
  }
}