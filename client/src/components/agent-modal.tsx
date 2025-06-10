import { useState, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { Agent, InsertAgent } from "@shared/schema";

interface AgentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  agent?: Agent | null;
  onSave: () => void;
}

const availableTools = ['nmap', 'gobuster', 'sqlmap', 'nuclei', 'metasploit', 'burpsuite', 'nikto', 'dirb', 'hydra', 'john'];

export default function AgentModal({ open, onOpenChange, agent, onSave }: AgentModalProps) {
  const [formData, setFormData] = useState<Partial<InsertAgent>>({
    name: "",
    type: "recon",
    description: "",
    instructions: "",
    expectedOutput: "",
    tools: [],
    status: "inactive",
  });

  const { toast } = useToast();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (agent) {
      setFormData(agent);
    } else {
      setFormData({
        name: "",
        type: "recon",
        description: "",
        instructions: "",
        expectedOutput: "",
        tools: [],
        status: "inactive",
      });
    }
  }, [agent, open]);

  const createAgentMutation = useMutation({
    mutationFn: async (data: InsertAgent) => {
      const response = await apiRequest("POST", "/api/agents", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/metrics"] });
      toast({
        title: "Success",
        description: "Agent created successfully",
      });
      onSave();
      onOpenChange(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to create agent",
        variant: "destructive",
      });
    },
  });

  const updateAgentMutation = useMutation({
    mutationFn: async (data: Partial<InsertAgent>) => {
      if (!agent?.id) throw new Error("No agent ID");
      const response = await apiRequest("PUT", `/api/agents/${agent.id}`, data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/metrics"] });
      toast({
        title: "Success",
        description: "Agent updated successfully",
      });
      onSave();
      onOpenChange(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update agent",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.name || !formData.description || !formData.instructions || !formData.expectedOutput) {
      toast({
        title: "Validation Error",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    if (agent) {
      updateAgentMutation.mutate(formData as Partial<InsertAgent>);
    } else {
      createAgentMutation.mutate(formData as InsertAgent);
    }
  };

  const handleToolChange = (tool: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      tools: checked 
        ? [...(prev.tools || []), tool]
        : (prev.tools || []).filter(t => t !== tool)
    }));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-auto">
        <DialogHeader>
          <DialogTitle>{agent ? "Edit Agent" : "Create New Agent"}</DialogTitle>
        </DialogHeader>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label htmlFor="name">Agent Name *</Label>
              <Input
                id="name"
                value={formData.name || ""}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                placeholder="Enter agent name"
                required
              />
            </div>
            <div>
              <Label htmlFor="type">Agent Type *</Label>
              <Select value={formData.type || ""} onValueChange={(value) => setFormData(prev => ({ ...prev, type: value }))}>
                <SelectTrigger>
                  <SelectValue placeholder="Select agent type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="recon">Reconnaissance</SelectItem>
                  <SelectItem value="exploit">Exploitation</SelectItem>
                  <SelectItem value="persistence">Persistence</SelectItem>
                  <SelectItem value="lateral">Lateral Movement</SelectItem>
                  <SelectItem value="collection">Data Collection</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div>
            <Label htmlFor="description">Description *</Label>
            <Textarea
              id="description"
              value={formData.description || ""}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Describe the agent's purpose and capabilities"
              className="h-20"
              required
            />
          </div>
          
          <div>
            <Label htmlFor="instructions">Instructions *</Label>
            <Textarea
              id="instructions"
              value={formData.instructions || ""}
              onChange={(e) => setFormData(prev => ({ ...prev, instructions: e.target.value }))}
              placeholder="Detailed instructions for the agent"
              className="h-24"
              required
            />
          </div>
          
          <div>
            <Label htmlFor="expectedOutput">Expected Output *</Label>
            <Textarea
              id="expectedOutput"
              value={formData.expectedOutput || ""}
              onChange={(e) => setFormData(prev => ({ ...prev, expectedOutput: e.target.value }))}
              placeholder="Define the expected output format"
              className="h-20"
              required
            />
          </div>
          
          <div>
            <Label>Available Tools</Label>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-2">
              {availableTools.map((tool) => (
                <div key={tool} className="flex items-center space-x-2">
                  <Checkbox
                    id={tool}
                    checked={formData.tools?.includes(tool) || false}
                    onCheckedChange={(checked) => handleToolChange(tool, !!checked)}
                  />
                  <Label htmlFor={tool} className="text-sm">{tool}</Label>
                </div>
              ))}
            </div>
          </div>
          
          <div className="flex justify-end space-x-3 pt-4">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button 
              type="submit" 
              disabled={createAgentMutation.isPending || updateAgentMutation.isPending}
            >
              {createAgentMutation.isPending || updateAgentMutation.isPending ? "Saving..." : (agent ? "Update Agent" : "Create Agent")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
