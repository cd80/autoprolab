import { Activity, Clock, Globe, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface StatusBarProps {
  metrics?: {
    activeAgents: number;
    compromisedHosts: number;
    flagsCaptured: string;
    mcpTools: number;
    targetCount: number;
    labProgress: string;
  };
}

export default function StatusBar({ metrics }: StatusBarProps) {
  const statusItems = [
    {
      icon: Activity,
      label: "Active Agents",
      value: metrics?.activeAgents || 0,
      color: "text-blue-400"
    },
    {
      icon: Globe,
      label: "Targets",
      value: metrics?.targetCount || 0,
      color: "text-green-400"
    },
    {
      icon: Zap,
      label: "Compromised",
      value: metrics?.compromisedHosts || 0,
      color: "text-red-400"
    },
    {
      icon: Clock,
      label: "Lab Progress",
      value: metrics?.labProgress || "0%",
      color: "text-amber-400"
    }
  ];

  return (
    <div className="h-12 bg-slate-800 border-t border-slate-700 px-6 flex items-center justify-between">
      <div className="flex items-center space-x-6">
        {statusItems.map((item, index) => {
          const Icon = item.icon;
          return (
            <div key={index} className="flex items-center space-x-2">
              <Icon className={`w-4 h-4 ${item.color}`} />
              <span className="text-sm text-slate-300">{item.label}:</span>
              <Badge variant="secondary" className="text-xs">
                {item.value}
              </Badge>
            </div>
          );
        })}
      </div>
      
      <div className="flex items-center space-x-2 text-xs text-slate-400">
        <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
        <span>System Online</span>
      </div>
    </div>
  );
}