import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/sidebar";
import NetworkTopology from "@/components/network-topology";
import AgentModal from "@/components/agent-modal";
import TargetModal from "@/components/target-modal";
import TeamHierarchy from "@/components/team-hierarchy";
import ADVisualization from "@/components/ad-visualization";
import ProLabSelection from "@/components/pro-lab-selection";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Activity, BarChart3, Bot, Crosshair, Flag, Plus, RefreshCw, 
  Search, Shield, Target as TargetIcon, Wrench, Download, Bug, ArrowsUpFromLine,
  Anchor, Server, Globe, Database, Save, TrendingUp, Users, Zap
} from "lucide-react";
import { formatRelativeTime, getStatusColor } from "@/lib/utils";
import type { Agent, Target, Activity as ActivityType, HtbLab } from "@shared/schema";

type TabType = "dashboard" | "agents" | "topology" | "targets" | "tools" | "htb" | "ad";

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<TabType>("dashboard");
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [showTargetModal, setShowTargetModal] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  // Queries
  const { data: metrics } = useQuery<{
    activeAgents: number;
    compromisedHosts: number;
    flagsCaptured: string;
    mcpTools: number;
    targetCount: number;
    labProgress: string;
  }>({
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

  const { data: mcpServers = [] } = useQuery<any[]>({
    queryKey: ["/api/mcp-servers"],
  });

  const { data: customTools = [] } = useQuery<any[]>({
    queryKey: ["/api/custom-tools"],
  });

  const handleTargetClick = (target: Target) => {
    setSelectedTarget(target);
    setShowTargetModal(true);
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Active Agents</p>
                <p className="text-3xl font-bold text-white">{metrics?.activeAgents || 0}</p>
              </div>
              <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                <Bot className="text-blue-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <TrendingUp className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">All operational</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Targets</p>
                <p className="text-3xl font-bold text-white">{metrics?.targetCount || 0}</p>
              </div>
              <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                <TargetIcon className="text-green-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-amber-400">{metrics?.compromisedHosts || 0} compromised</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Flags Captured</p>
                <p className="text-3xl font-bold text-white">{metrics?.flagsCaptured || "0/0"}</p>
              </div>
              <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center">
                <Flag className="text-red-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-blue-400">{metrics?.labProgress || "0%"} complete</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">MCP Tools</p>
                <p className="text-3xl font-bold text-white">{metrics?.mcpTools || 0}</p>
              </div>
              <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                <Wrench className="text-purple-400 text-xl" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-green-400">All online</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activities */}
        <Card className="lg:col-span-2 bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              Recent Activities
              <Button size="sm" variant="ghost">
                <RefreshCw className="w-4 h-4" />
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {activities.length === 0 ? (
                <p className="text-slate-400 text-center py-8">No recent activities</p>
              ) : (
                activities.slice(0, 8).map((activity) => (
                  <div key={activity.id} className="flex items-center space-x-3 p-3 bg-slate-700/50 rounded-lg">
                    <Activity className="w-4 h-4 text-blue-400" />
                    <div className="flex-1">
                      <p className="text-sm font-medium text-white">{activity.action}</p>
                      <p className="text-xs text-slate-400">{activity.description}</p>
                    </div>
                    <div className="text-right">
                      <Badge className={getStatusColor(activity.status)}>{activity.status}</Badge>
                      <p className="text-xs text-slate-500 mt-1">{formatRelativeTime(activity.createdAt)}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* Target Summary */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle>Active Targets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {targets.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No targets available</p>
              ) : (
                targets.slice(0, 5).map((target) => (
                  <div 
                    key={target.id} 
                    className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg cursor-pointer hover:bg-slate-700 transition-colors"
                    onClick={() => handleTargetClick(target)}
                  >
                    <div className="flex items-center space-x-3">
                      <div className={`w-3 h-3 rounded-full ${
                        target.status === 'compromised' ? 'bg-green-400' :
                        target.status === 'in-progress' ? 'bg-amber-400' : 'bg-slate-400'
                      }`}></div>
                      <div>
                        <p className="text-sm font-medium text-white">{target.hostname}</p>
                        <p className="text-xs text-slate-400">{target.ipAddress}</p>
                      </div>
                    </div>
                    <Badge className={getStatusColor(target.status)}>
                      {target.status}
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-2xl font-bold">Agent Management</h3>
        <Button onClick={() => setShowAgentModal(true)} className="btn-primary">
          <Plus className="w-4 h-4 mr-2" />
          Create Agent
        </Button>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle>Active Agents</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {agents.length === 0 ? (
                <p className="text-slate-400 text-center py-8">No agents deployed</p>
              ) : (
                agents.map((agent) => (
                  <div key={agent.id} className="p-4 bg-slate-700/50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-white">{agent.name}</h4>
                      <Badge className={getStatusColor(agent.status)}>{agent.status}</Badge>
                    </div>
                    <p className="text-sm text-slate-400 mb-3">{agent.description}</p>
                    <div className="flex items-center text-xs text-slate-500">
                      <Users className="w-3 h-3 mr-1" />
                      Team: {agent.teamId || "Unassigned"}
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        <TeamHierarchy />
      </div>
    </div>
  );

  const renderTargets = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-2xl font-bold">Target Analysis</h3>
        <div className="flex space-x-2">
          <Button variant="secondary" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button variant="secondary" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Scan
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {targets.map((target) => (
          <Card key={target.id} className="bg-slate-800 border-slate-700 cursor-pointer hover:bg-slate-750 transition-colors"
                onClick={() => handleTargetClick(target)}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">{target.hostname}</CardTitle>
                <Badge className={getStatusColor(target.status)}>{target.status}</Badge>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center text-sm">
                  <Globe className="w-4 h-4 mr-2 text-slate-400" />
                  <span className="text-slate-300">{target.ipAddress}</span>
                </div>
                <div className="flex items-center text-sm">
                  <Server className="w-4 h-4 mr-2 text-slate-400" />
                  <span className="text-slate-300">{target.operatingSystem}</span>
                </div>
                {target.openPorts && target.openPorts.length > 0 && (
                  <div className="text-sm">
                    <span className="text-slate-400">Open Ports: </span>
                    <span className="text-slate-300">{target.openPorts.slice(0, 3).map(p => p.port).join(', ')}</span>
                    {target.openPorts.length > 3 && <span className="text-slate-500"> +{target.openPorts.length - 3} more</span>}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );

  const renderTools = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-2xl font-bold">Tool Registry</h3>
        <Button className="btn-primary">
          <Plus className="w-4 h-4 mr-2" />
          Add Tool
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* MCP Servers */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle>MCP Servers</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {mcpServers.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No MCP servers configured</p>
              ) : (
                mcpServers.map((server) => (
                  <div key={server.id} className="p-3 bg-slate-700/50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-medium text-white">{server.name}</h4>
                      <Badge className={getStatusColor(server.status)}>{server.status}</Badge>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">{server.description}</p>
                    <div className="flex items-center space-x-4 text-xs">
                      <span className="text-slate-500">URL: {server.url}</span>
                      <span className="text-slate-500">Tools: {server.tools?.length || 0}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* Custom Tools */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle>Custom Tools</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {customTools.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No custom tools available</p>
              ) : (
                customTools.map((tool) => (
                  <div key={tool.id} className="p-3 bg-slate-700/50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-medium text-white">{tool.name}</h4>
                      <Badge className={getStatusColor(tool.status)}>{tool.status}</Badge>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">{tool.description}</p>
                    <div className="flex items-center space-x-4 text-xs">
                      <span className="text-slate-500">Language: {tool.language}</span>
                      <span className="text-slate-500">Version: {tool.version}</span>
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-2xl font-bold">Hack The Box Labs</h3>
        <Button variant="secondary" size="sm">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh Status
        </Button>
      </div>
      
      <ProLabSelection activeHtbLab={activeHtbLab} />
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="flex h-screen">
        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={(tab: string) => setActiveTab(tab as TabType)}
          metrics={metrics}
          onCreateAgent={() => setShowAgentModal(true)}
        />
        
        <main className="flex-1 overflow-auto bg-slate-900">
          <div className="p-6 h-full">
            {activeTab === "dashboard" && renderDashboard()}
            {activeTab === "agents" && renderAgents()}
            {activeTab === "topology" && <NetworkTopology />}
            {activeTab === "targets" && renderTargets()}
            {activeTab === "tools" && renderTools()}
            {activeTab === "htb" && renderHTB()}
            {activeTab === "ad" && <ADVisualization />}
          </div>
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