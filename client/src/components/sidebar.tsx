import { Shield, BarChart3, Bot, Target, Bolt, Flag } from "lucide-react";
import { cn } from "@/lib/utils";

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  metrics?: any;
  onCreateAgent: () => void;
}

export default function Sidebar({ activeTab, setActiveTab, metrics, onCreateAgent }: SidebarProps) {
  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: BarChart3 },
    { id: "agents", label: "Agent Management", icon: Bot },
    { id: "topology", label: "Network Topology", icon: Target },
    { id: "targets", label: "Target Analysis", icon: Target },
    { id: "tools", label: "Tool Registry", icon: Bolt },
    { id: "htb", label: "HTB Progress", icon: Flag },
  ];

  return (
    <div className="w-64 bg-slate-950 border-r border-slate-700 flex flex-col">
      {/* Logo/Header */}
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center">
            <Shield className="text-white text-sm" />
          </div>
          <h1 className="text-xl font-bold text-white">RedTeam CC</h1>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={cn(
                "nav-item w-full text-left",
                activeTab === item.id && "active"
              )}
            >
              <Icon className="w-5 h-5" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Status Panel */}
      <div className="p-4 border-t border-slate-700">
        <div className="text-xs text-slate-400 mb-2">System Status</div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm">Active Agents</span>
            <span className="text-blue-400 font-medium">{metrics?.activeAgents || 0}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Targets</span>
            <span className="text-green-400 font-medium">{metrics?.targetCount || 0}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Lab Progress</span>
            <span className="text-amber-400 font-medium">{metrics?.labProgress || "0%"}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
