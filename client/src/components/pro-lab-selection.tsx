import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Flag, 
  Play, 
  Square, 
  RefreshCw, 
  Globe, 
  Clock,
  Users,
  Award,
  Loader2
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { HtbLab } from "@shared/schema";

interface ProLab {
  id: string;
  name: string;
  difficulty: "Easy" | "Medium" | "Hard" | "Insane";
  machines: number;
  flags: number;
  description: string;
  estimatedTime: string;
  userProgress?: {
    capturedFlags: number;
    completionPercentage: number;
    isActive: boolean;
  };
}

interface ProLabSelectionProps {
  activeHtbLab?: HtbLab;
}

export default function ProLabSelection({ activeHtbLab }: ProLabSelectionProps) {
  const [selectedLabId, setSelectedLabId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Fetch available Pro Labs using htb-operator
  const { data: proLabs = [], isLoading: isLoadingLabs, refetch: refetchLabs } = useQuery<ProLab[]>({
    queryKey: ["/api/htb-operator/labs"],
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Start Pro Lab mutation
  const startLabMutation = useMutation({
    mutationFn: async (labId: string) => {
      const response = await fetch(`/api/htb-operator/labs/${labId}/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!response.ok) throw new Error("Failed to start lab");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/htb-labs/active"] });
      queryClient.invalidateQueries({ queryKey: ["/api/htb-operator/labs"] });
      toast({
        title: "Pro Lab Started",
        description: "Successfully connected to the Pro Lab environment",
      });
    },
    onError: () => {
      toast({
        title: "Connection Failed", 
        description: "Failed to start Pro Lab. Check htb-operator configuration.",
        variant: "destructive",
      });
    },
  });

  // Stop Pro Lab mutation
  const stopLabMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch(`/api/htb-operator/labs/stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!response.ok) throw new Error("Failed to stop lab");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/htb-labs/active"] });
      queryClient.invalidateQueries({ queryKey: ["/api/htb-operator/labs"] });
      toast({
        title: "Pro Lab Stopped",
        description: "Disconnected from Pro Lab environment",
      });
    },
    onError: () => {
      toast({
        title: "Disconnect Failed",
        description: "Failed to stop Pro Lab connection",
        variant: "destructive", 
      });
    },
  });

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Easy": return "bg-green-500/20 text-green-400 border-green-500/50";
      case "Medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50";
      case "Hard": return "bg-orange-500/20 text-orange-400 border-orange-500/50";
      case "Insane": return "bg-red-500/20 text-red-400 border-red-500/50";
      default: return "bg-slate-500/20 text-slate-400 border-slate-500/50";
    }
  };

  const handleStartLab = async (labId: string) => {
    setSelectedLabId(labId);
    await startLabMutation.mutateAsync(labId);
    setSelectedLabId(null);
  };

  const handleStopLab = async () => {
    await stopLabMutation.mutateAsync();
  };

  const handleRefreshLabs = () => {
    refetchLabs();
    toast({
      title: "Labs Refreshed",
      description: "Pro Lab list updated from htb-operator",
    });
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center space-x-2">
            <Globe className="w-5 h-5" />
            <span>HTB Pro Lab Selection</span>
          </CardTitle>
          <div className="flex items-center space-x-2">
            {activeHtbLab && (
              <Button
                variant="destructive"
                size="sm"
                onClick={handleStopLab}
                disabled={stopLabMutation.isPending}
              >
                {stopLabMutation.isPending ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <Square className="w-3 h-3" />
                )}
                Disconnect
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefreshLabs}
              disabled={isLoadingLabs}
            >
              {isLoadingLabs ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <RefreshCw className="w-3 h-3" />
              )}
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoadingLabs ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
            <span className="ml-2 text-slate-400">Loading Pro Labs...</span>
          </div>
        ) : proLabs.length === 0 ? (
          <div className="text-center py-8">
            <Globe className="w-12 h-12 text-slate-400 mx-auto mb-4" />
            <p className="text-slate-400">No Pro Labs available</p>
            <p className="text-sm text-slate-500">Check htb-operator connection</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {proLabs.map((lab) => (
              <div
                key={lab.id}
                className={`relative p-4 rounded-lg border-2 transition-all hover:shadow-lg ${
                  activeHtbLab?.name === lab.name
                    ? "border-green-500 bg-green-500/10"
                    : "border-slate-600 bg-slate-800/50 hover:border-slate-500"
                }`}
              >
                {/* Lab Status Badge */}
                {lab.userProgress?.isActive && (
                  <div className="absolute top-2 right-2">
                    <div className="flex items-center space-x-1 bg-green-500/20 px-2 py-1 rounded-full">
                      <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                      <span className="text-xs text-green-400">Active</span>
                    </div>
                  </div>
                )}

                <div className="mb-3">
                  <h3 className="font-semibold text-white mb-2">{lab.name}</h3>
                  <p className="text-sm text-slate-400 mb-3 line-clamp-2">
                    {lab.description}
                  </p>

                  <div className="flex items-center space-x-2 mb-3">
                    <Badge className={`text-xs ${getDifficultyColor(lab.difficulty)}`}>
                      {lab.difficulty}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 mb-3">
                    <div className="flex items-center space-x-1">
                      <Users className="w-3 h-3" />
                      <span>{lab.machines} machines</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Flag className="w-3 h-3" />
                      <span>{lab.flags} flags</span>
                    </div>
                    <div className="flex items-center space-x-1 col-span-2">
                      <Clock className="w-3 h-3" />
                      <span>Est. {lab.estimatedTime}</span>
                    </div>
                  </div>

                  {/* Progress for started labs */}
                  {lab.userProgress && lab.userProgress.capturedFlags > 0 && (
                    <div className="mb-3">
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="text-slate-400">Progress</span>
                        <span className="text-white">
                          {lab.userProgress.capturedFlags}/{lab.flags} flags
                        </span>
                      </div>
                      <Progress 
                        value={lab.userProgress.completionPercentage} 
                        className="h-1" 
                      />
                    </div>
                  )}
                </div>

                <Button
                  className="w-full"
                  variant={activeHtbLab?.name === lab.name ? "destructive" : "default"}
                  size="sm"
                  onClick={() => 
                    activeHtbLab?.name === lab.name 
                      ? handleStopLab() 
                      : handleStartLab(lab.id)
                  }
                  disabled={
                    startLabMutation.isPending || 
                    stopLabMutation.isPending || 
                    selectedLabId === lab.id
                  }
                >
                  {selectedLabId === lab.id ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : activeHtbLab?.name === lab.name ? (
                    <>
                      <Square className="w-3 h-3 mr-1" />
                      Disconnect
                    </>
                  ) : (
                    <>
                      <Play className="w-3 h-3 mr-1" />
                      Start Lab
                    </>
                  )}
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}