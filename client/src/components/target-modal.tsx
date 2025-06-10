import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { getStatusColor } from "@/lib/utils";
import { Search, Shield, Bug, ArrowsUpFromLine, Download, Anchor } from "lucide-react";
import type { Target } from "@shared/schema";

interface TargetModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  target: Target | null;
}

export default function TargetModal({ open, onOpenChange, target }: TargetModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const actionMutation = useMutation({
    mutationFn: async ({ action, agentId }: { action: string, agentId?: number }) => {
      if (!target) throw new Error("No target selected");
      const response = await apiRequest("POST", `/api/targets/${target.id}/actions/${action}`, { agentId });
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/activities"] });
      queryClient.invalidateQueries({ queryKey: ["/api/targets"] });
      toast({
        title: "Action Started",
        description: data.message,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to start action",
        variant: "destructive",
      });
    },
  });

  const handleAction = (action: string) => {
    actionMutation.mutate({ action });
  };

  if (!target) return null;

  const actions = [
    { id: "recon", label: "Reconnaissance", icon: Search, description: "Scan ports and enumerate services" },
    { id: "vulnerability-scan", label: "Vulnerability Scan", icon: Shield, description: "Identify security vulnerabilities" },
    { id: "exploit", label: "Exploit", icon: Bug, description: "Attempt to exploit identified vulnerabilities" },
    { id: "lateral-movement", label: "Lateral Movement", icon: ArrowsUpFromLine, description: "Move to adjacent systems" },
    { id: "collect-info", label: "Collect Info", icon: Download, description: "Gather system information and data" },
    { id: "persistence", label: "Persistence", icon: Anchor, description: "Establish persistent access" },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-auto">
        <DialogHeader>
          <DialogTitle>Target Details - {target.hostname}</DialogTitle>
        </DialogHeader>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Target Info */}
          <div>
            <h4 className="text-lg font-semibold text-white mb-4">System Information</h4>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-slate-400">Hostname:</span>
                <span className="text-white">{target.hostname}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">IP Address:</span>
                <span className="text-white">{target.ipAddress}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Operating System:</span>
                <span className="text-white">{target.operatingSystem || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Network Segment:</span>
                <span className="text-white">{target.networkSegment || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status:</span>
                <Badge className={getStatusColor(target.status)}>
                  {target.status.charAt(0).toUpperCase() + target.status.slice(1)}
                </Badge>
              </div>
            </div>

            <h4 className="text-lg font-semibold text-white mb-4 mt-6">Open Ports</h4>
            <div className="space-y-2 max-h-32 overflow-y-auto">
              {target.openPorts && target.openPorts.length > 0 ? (
                target.openPorts.map((port, index) => (
                  <div key={index} className="flex justify-between p-2 bg-slate-800/50 rounded">
                    <span className="text-white">{port.port}/tcp</span>
                    <span className="text-slate-400">{port.service}</span>
                  </div>
                ))
              ) : (
                <p className="text-slate-400 text-sm">No open ports identified</p>
              )}
            </div>

            <h4 className="text-lg font-semibold text-white mb-4 mt-6">Vulnerabilities</h4>
            <div className="space-y-2 max-h-24 overflow-y-auto">
              {target.vulnerabilities && target.vulnerabilities.length > 0 ? (
                target.vulnerabilities.map((vuln, index) => (
                  <div key={index} className="p-2 bg-red-500/20 text-red-300 rounded text-sm">
                    {vuln}
                  </div>
                ))
              ) : (
                <p className="text-slate-400 text-sm">No vulnerabilities identified</p>
              )}
            </div>

            <h4 className="text-lg font-semibold text-white mb-4 mt-6">Flags</h4>
            <div className="space-y-2">
              {target.flags && target.flags.length > 0 ? (
                target.flags.map((flag, index) => (
                  <div key={index} className="flex justify-between items-center p-2 bg-slate-800/50 rounded">
                    <span className="text-white capitalize">{flag.type} Flag</span>
                    <Badge className={getStatusColor(flag.status)}>
                      {flag.status.charAt(0).toUpperCase() + flag.status.slice(1)}
                    </Badge>
                  </div>
                ))
              ) : (
                <p className="text-slate-400 text-sm">No flags defined</p>
              )}
            </div>
          </div>

          {/* Actions */}
          <div>
            <h4 className="text-lg font-semibold text-white mb-4">Red Team Actions</h4>
            <div className="grid grid-cols-2 gap-3">
              {actions.map((action) => {
                const Icon = action.icon;
                return (
                  <button
                    key={action.id}
                    onClick={() => handleAction(action.id)}
                    disabled={actionMutation.isPending}
                    className="btn-action"
                  >
                    <Icon className="text-2xl text-blue-400" />
                    <span>{action.label}</span>
                  </button>
                );
              })}
            </div>

            <h4 className="text-lg font-semibold text-white mb-4 mt-6">Agent Assignment</h4>
            <Select>
              <SelectTrigger className="mb-3">
                <SelectValue placeholder="Select Agent" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">No Agent Selected</SelectItem>
                <SelectItem value="recon">Recon Agent</SelectItem>
                <SelectItem value="exploit">Exploit Agent</SelectItem>
                <SelectItem value="persistence">Persistence Agent</SelectItem>
              </SelectContent>
            </Select>
            <Button className="w-full" disabled={actionMutation.isPending}>
              {actionMutation.isPending ? "Processing..." : "Assign Agent"}
            </Button>

            {target.assignedAgentId && (
              <div className="mt-4 p-3 bg-blue-500/20 border border-blue-500/30 rounded-lg">
                <p className="text-sm text-blue-300">
                  Agent #{target.assignedAgentId} is currently assigned to this target
                </p>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
