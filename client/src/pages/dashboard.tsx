import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/sidebar";
import NetworkTopology from "@/components/network-topology";
import AgentModal from "@/components/agent-modal";
import TargetModal from "@/components/target-modal";
import TeamHierarchy from "@/components/team-hierarchy";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { 
  Activity, BarChart3, Bot, Crosshair, Flag, Plus, RefreshCw, 
  Search, Shield, Target, Bolt, Download, Bug, ArrowsUpFromLine,
  Anchor, Server, Globe, Database, Save
} from "lucide-react";
import { formatRelativeTime, getStatusColor } from "@/lib/utils";
import type { Agent, Target, Activity as ActivityType, HtbLab } from "@shared/schema";

type TabType = "dashboard" | "agents" | "topology" | "targets" | "tools" | "htb";

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<TabType>("dashboard");
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [showTargetModal, setShowTargetModal] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  // Queries
  const { data: metrics } = useQuery({
    queryKey: ["/api/dashboard/metrics"],
  });

  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ["/api/agents"],
  });

  const { data: targets = [] } = useQuery<Target[]>({
    queryKey: ["/api/targets"],
  });

  const { data: activities = [] } = useQuery<ActivityType[]>({
    queryKey: ["/api/activities", { limit: 10 }],
  });

  const { data: activeHtbLab } = useQuery<HtbLab>({
    queryKey: ["/api/htb-labs/active"],
  });

  const { data: mcpServers = [] } = useQuery({
    queryKey: ["/api/mcp-servers"],
  });

  const { data: customTools = [] } = useQuery({
    queryKey: ["/api/custom-tools"],
  });

  const tabInfo = {
    dashboard: { title: 'Command Dashboard', subtitle: 'Monitor and control your red team operations' },
    agents: { title: 'Agent Management', subtitle: 'Configure and deploy AI agents for red team operations' },
    topology: { title: 'Network Topology', subtitle: 'Visualize target network infrastructure' },
    targets: { title: 'Target Analysis', subtitle: 'Detailed target information and attack vectors' },
    tools: { title: 'Tool Registry', subtitle: 'Manage MCP servers and custom tools' },
    htb: { title: 'HTB Progress', subtitle: 'Track Hack The Box Pro Lab progress and flags' }
  };

  const handleTargetClick = (target: Target) => {
    setSelectedTarget(target);
    setShowTargetModal(true);
  };

  const renderDashboard = () => (
    <div className="p-6 space-y-6">
      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Active Agents</p>
                <p className="text-2xl font-bold text-white">{metrics?.activeAgents || 0}</p>
              </div>
              <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                <Bot className="text-blue-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-green-400">+{Math.floor(Math.random() * 3)}</span>
              <span className="text-slate-400 ml-1">from last hour</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Compromised Hosts</p>
                <p className="text-2xl font-bold text-white">{metrics?.compromisedHosts || 0}</p>
              </div>
              <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                <Server className="text-green-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-green-400">+1</span>
              <span className="text-slate-400 ml-1">new this session</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Flags Captured</p>
                <p className="text-2xl font-bold text-white">{metrics?.flagsCaptured || "0/0"}</p>
              </div>
              <div className="w-12 h-12 bg-amber-500/20 rounded-xl flex items-center justify-center">
                <Flag className="text-amber-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-amber-400">{metrics?.labProgress || "0%"}</span>
              <span className="text-slate-400 ml-1">completion</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">MCP Bolt</p>
                <p className="text-2xl font-bold text-white">{metrics?.mcpTools || 0}</p>
              </div>
              <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                <Bolt className="text-purple-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-green-400">All online</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Agent Activity & Target Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Agent Activity */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Agent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {activities.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No recent activity</p>
              ) : (
                activities.slice(0, 5).map((activity) => (
                  <div key={activity.id} className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
                      <Activity className="text-blue-400 text-sm" />
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-white">{activity.action}</p>
                      <p className="text-xs text-slate-400">{activity.description}</p>
                    </div>
                    <span className="text-xs text-slate-500">
                      {formatRelativeTime(activity.createdAt)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* Target Summary */}
        <Card>
          <CardHeader>
            <CardTitle>Target Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {targets.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No targets available</p>
              ) : (
                targets.slice(0, 5).map((target) => (
                  <div key={target.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className={`w-2 h-2 rounded-full ${
                        target.status === 'compromised' ? 'bg-green-400' :
                        target.status === 'in-progress' ? 'bg-amber-400' : 'bg-slate-400'
                      }`}></div>
                      <div>
                        <p className="text-sm font-medium text-white">{target.hostname}</p>
                        <p className="text-xs text-slate-400">{target.operatingSystem}</p>
                      </div>
                    </div>
                    <Badge className={getStatusColor(target.status)}>
                      {target.status.charAt(0).toUpperCase() + target.status.slice(1)}
                    </Badge>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );

  const renderAgents = () => (
    <div className="p-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Team Hierarchy */}
        <div className="lg:col-span-1">
          <Card className="h-full">
            <CardHeader>
              <CardTitle>Team Hierarchy</CardTitle>
              <Button size="sm" variant="secondary">
                <Plus className="w-3 h-3" />
                Add Team
              </Button>
            </CardHeader>
            <CardContent>
              <TeamHierarchy />
            </CardContent>
          </Card>
        </div>

        {/* Agent Details */}
        <div className="lg:col-span-2">
          <Card className="h-full">
            <CardHeader>
              <CardTitle>Agent Configuration</CardTitle>
              <Button size="sm" className="btn-primary">
                <Save className="w-3 h-3" />
                Save
              </Button>
            </CardHeader>
            <CardContent>
              <form className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label>Agent Name</Label>
                    <Input placeholder="Enter agent name" value={selectedAgent?.name || ""} />
                  </div>
                  <div>
                    <Label>Agent Type</Label>
                    <Select value={selectedAgent?.type || ""}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select agent type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="recon">Reconnaissance</SelectItem>
                        <SelectItem value="exploit">Exploitation</SelectItem>
                        <SelectItem value="persistence">Persistence</SelectItem>
                        <SelectItem value="lateral">Lateral Movement</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label>Description</Label>
                  <Textarea 
                    placeholder="Describe the agent's purpose and capabilities" 
                    value={selectedAgent?.description || ""}
                    className="h-20"
                  />
                </div>
                <div>
                  <Label>Instructions</Label>
                  <Textarea 
                    placeholder="Detailed instructions for the agent" 
                    value={selectedAgent?.instructions || ""}
                    className="h-24"
                  />
                </div>
                <div>
                  <Label>Expected Output</Label>
                  <Textarea 
                    placeholder="Define the expected output format" 
                    value={selectedAgent?.expectedOutput || ""}
                    className="h-20"
                  />
                </div>
                <div>
                  <Label>Available Bolt</Label>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-2">
                    {['nmap', 'gobuster', 'sqlmap', 'nuclei', 'metasploit', 'burpsuite'].map((tool) => (
                      <div key={tool} className="flex items-center space-x-2">
                        <Checkbox 
                          id={tool} 
                          checked={selectedAgent?.tools?.includes(tool) || false}
                        />
                        <Label htmlFor={tool} className="text-sm">{tool}</Label>
                      </div>
                    ))}
                  </div>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );

  const renderTargets = () => (
    <div className="p-6 space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {targets.length === 0 ? (
          <div className="col-span-full text-center py-12">
            <Target className="w-12 h-12 text-slate-400 mx-auto mb-4" />
            <p className="text-slate-400">No targets available</p>
            <p className="text-sm text-slate-500">Add your first target to begin analysis</p>
          </div>
        ) : (
          targets.map((target) => (
            <Card 
              key={target.id} 
              className="cursor-pointer hover:border-blue-500/50 transition-colors"
              onClick={() => handleTargetClick(target)}
            >
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className={`w-12 h-12 ${getStatusColor(target.status)} rounded-xl flex items-center justify-center`}>
                      {target.operatingSystem?.toLowerCase().includes('windows') ? (
                        <Server className="text-xl" />
                      ) : target.operatingSystem?.toLowerCase().includes('web') ? (
                        <Globe className="text-xl" />
                      ) : target.operatingSystem?.toLowerCase().includes('sql') ? (
                        <Database className="text-xl" />
                      ) : (
                        <Server className="text-xl" />
                      )}
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{target.hostname}</h3>
                      <p className="text-sm text-slate-400">{target.operatingSystem}</p>
                    </div>
                  </div>
                  <Badge className={getStatusColor(target.status)}>
                    {target.status.charAt(0).toUpperCase() + target.status.slice(1)}
                  </Badge>
                </div>
                <div className="space-y-2 mb-4">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">IP Address:</span>
                    <span className="text-white">{target.ipAddress}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">OS:</span>
                    <span className="text-white">{target.operatingSystem}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Flags:</span>
                    <span className="text-white">
                      {target.flags?.filter(f => f.status === 'captured').length || 0}/{target.flags?.length || 0}
                    </span>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <Button size="sm" className="flex-1">
                    <Search className="w-3 h-3" />
                    Recon
                  </Button>
                  <Button size="sm" variant="secondary" className="flex-1">
                    <Bug className="w-3 h-3" />
                    Exploit
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );

  const renderTools = () => (
    <div className="p-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* MCP Servers */}
        <Card>
          <CardHeader>
            <CardTitle>MCP Servers</CardTitle>
            <Button size="sm" className="btn-primary">
              <Plus className="w-3 h-3" />
              Add Server
            </Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {mcpServers.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No MCP servers configured</p>
              ) : (
                mcpServers.map((server: any) => (
                  <div key={server.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className={`w-2 h-2 rounded-full ${
                        server.status === 'online' ? 'bg-green-400' : 'bg-amber-400'
                      }`}></div>
                      <div>
                        <p className="text-sm font-medium text-white">{server.name}</p>
                        <p className="text-xs text-slate-400">{server.url}</p>
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <Button size="sm" variant="secondary">Configure</Button>
                      <Button size="sm" variant="destructive">Remove</Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* Custom Bolt */}
        <Card>
          <CardHeader>
            <CardTitle>Custom Bolt</CardTitle>
            <Button size="sm" className="btn-primary">
              <Plus className="w-3 h-3" />
              Add Tool
            </Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {customTools.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No custom tools available</p>
              ) : (
                customTools.map((tool: any) => (
                  <div key={tool.id} className="p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-medium text-white">{tool.name}</h4>
                      <div className="flex space-x-2">
                        <Button size="sm" variant="secondary">Edit</Button>
                        <Button size="sm" variant="destructive">Delete</Button>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">{tool.description}</p>
                    <div className="flex items-center space-x-4 text-xs">
                      <span className="text-slate-500">Language: {tool.language}</span>
                      <span className="text-slate-500">Version: {tool.version}</span>
                      <Badge className={getStatusColor(tool.status)}>{tool.status}</Badge>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );

  const renderHTB = () => (
    <div className="p-6 space-y-6">
      {/* Lab Overview */}
      {activeHtbLab ? (
        <Card>
          <CardHeader>
            <CardTitle>Active Pro Lab: {activeHtbLab.name}</CardTitle>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-sm text-green-400">Connected</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-white">{activeHtbLab.capturedFlags}</div>
                <div className="text-sm text-slate-400">Flags Obtained</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-slate-400">{activeHtbLab.totalFlags}</div>
                <div className="text-sm text-slate-400">Total Flags</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400">{activeHtbLab.completionPercentage}%</div>
                <div className="text-sm text-slate-400">Completion</div>
              </div>
            </div>
            <Progress value={activeHtbLab.completionPercentage} className="h-2" />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="text-center py-12">
            <Flag className="w-12 h-12 text-slate-400 mx-auto mb-4" />
            <p className="text-slate-400">No active HTB Pro Lab</p>
            <p className="text-sm text-slate-500">Connect to a lab to track progress</p>
          </CardContent>
        </Card>
      )}

      {/* Flag Progress */}
      <Card>
        <CardHeader>
          <CardTitle>Flag Progress</CardTitle>
          <Button size="sm" variant="secondary">
            <RefreshCw className="w-3 h-3" />
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {!activeHtbLab || !targets.length ? (
              <p className="text-slate-400 text-center py-4">No flags to display</p>
            ) : (
              targets.flatMap(target => 
                target.flags?.map(flag => (
                  <div key={flag.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Flag className={`${
                        flag.status === 'captured' ? 'text-green-400' : 
                        flag.status === 'in-progress' ? 'text-amber-400' : 'text-slate-400'
                      }`} />
                      <div>
                        <p className="text-sm font-medium text-white">
                          {flag.type.charAt(0).toUpperCase() + flag.type.slice(1)} Flag - {target.hostname}
                        </p>
                        <p className="text-xs text-slate-400">
                          {flag.status === 'captured' ? 'Successfully captured' : 
                           flag.status === 'in-progress' ? 'Exploitation in progress' : 'Awaiting completion'}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge className={getStatusColor(flag.status)}>
                        {flag.status.charAt(0).toUpperCase() + flag.status.slice(1)}
                      </Badge>
                      {flag.capturedAt && (
                        <span className="text-xs text-slate-500">
                          {formatRelativeTime(flag.capturedAt)}
                        </span>
                      )}
                    </div>
                  </div>
                )) || []
              )
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden bg-slate-900">
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab}
        metrics={metrics}
        onCreateAgent={() => setShowAgentModal(true)}
      />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">{tabInfo[activeTab].title}</h2>
              <p className="text-sm text-slate-400">{tabInfo[activeTab].subtitle}</p>
            </div>
            <div className="flex items-center space-x-4">
              <Button onClick={() => setShowAgentModal(true)}>
                <Plus className="w-4 h-4" />
                New Agent
              </Button>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-sm text-slate-300">Live</span>
              </div>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-auto">
          {activeTab === "dashboard" && renderDashboard()}
          {activeTab === "agents" && renderAgents()}
          {activeTab === "topology" && <NetworkTopology />}
          {activeTab === "targets" && renderTargets()}
          {activeTab === "tools" && renderTools()}
          {activeTab === "htb" && renderHTB()}
        </main>
      </div>

      {/* Modals */}
      <AgentModal 
        open={showAgentModal} 
        onOpenChange={setShowAgentModal}
        agent={selectedAgent}
        onSave={() => setShowAgentModal(false)}
      />
      
      <TargetModal 
        open={showTargetModal} 
        onOpenChange={setShowTargetModal}
        target={selectedTarget}
      />
    </div>
  );
}
