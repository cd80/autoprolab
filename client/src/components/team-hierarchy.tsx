import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { ChevronDown, ChevronRight, Users, Bot, Plus, MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { Team, Agent } from "@shared/schema";

interface TeamNode extends Team {
  children?: TeamNode[];
  agents?: Agent[];
}

export default function TeamHierarchy() {
  const [expandedTeams, setExpandedTeams] = useState<Set<number>>(new Set([1])); // Expand first team by default
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: teams = [] } = useQuery<Team[]>({
    queryKey: ["/api/teams"],
  });

  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ["/api/agents"],
  });

  // Build hierarchical structure
  const buildHierarchy = (teams: Team[], agents: Agent[]): TeamNode[] => {
    const teamMap = new Map<number, TeamNode>();
    const rootTeams: TeamNode[] = [];

    // Create team nodes
    teams.forEach(team => {
      teamMap.set(team.id, { ...team, children: [], agents: [] });
    });

    // Assign agents to teams
    agents.forEach(agent => {
      if (agent.teamId) {
        const team = teamMap.get(agent.teamId);
        if (team) {
          team.agents = team.agents || [];
          team.agents.push(agent);
        }
      }
    });

    // Build hierarchy
    teams.forEach(team => {
      const teamNode = teamMap.get(team.id);
      if (teamNode) {
        if (team.parentTeamId) {
          const parent = teamMap.get(team.parentTeamId);
          if (parent) {
            parent.children = parent.children || [];
            parent.children.push(teamNode);
          }
        } else {
          rootTeams.push(teamNode);
        }
      }
    });

    return rootTeams;
  };

  const hierarchy = buildHierarchy(teams, agents);

  const toggleTeam = (teamId: number) => {
    setExpandedTeams(prev => {
      const newSet = new Set(prev);
      if (newSet.has(teamId)) {
        newSet.delete(teamId);
      } else {
        newSet.add(teamId);
      }
      return newSet;
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-400';
      case 'busy':
        return 'text-amber-400';
      case 'inactive':
      default:
        return 'text-slate-400';
    }
  };

  const getAgentTypeIcon = (type: string) => {
    switch (type) {
      case 'recon':
        return '🔍';
      case 'exploit':
        return '💥';
      case 'persistence':
        return '🔒';
      case 'lateral':
        return '↔️';
      case 'collection':
        return '📊';
      default:
        return '🤖';
    }
  };

  const renderTeamNode = (team: TeamNode, depth: number = 0) => {
    const isExpanded = expandedTeams.has(team.id);
    const hasChildren = (team.children && team.children.length > 0) || (team.agents && team.agents.length > 0);

    return (
      <div key={team.id} className="select-none">
        {/* Team Header */}
        <div
          className={cn(
            "flex items-center space-x-2 p-2 rounded hover:bg-slate-700/50 cursor-pointer transition-colors",
            depth > 0 && "ml-6"
          )}
          onClick={() => hasChildren && toggleTeam(team.id)}
        >
          {hasChildren ? (
            isExpanded ? (
              <ChevronDown className="w-4 h-4 text-slate-400" />
            ) : (
              <ChevronRight className="w-4 h-4 text-slate-400" />
            )
          ) : (
            <div className="w-4 h-4" />
          )}
          
          <Users className={cn(
            "w-4 h-4",
            depth === 0 ? "text-blue-400" : "text-purple-400"
          )} />
          
          <span className="text-sm font-medium text-white flex-1">
            {team.name}
          </span>
          
          <div className="flex items-center space-x-1">
            {team.agents && team.agents.length > 0 && (
              <span className="text-xs text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                {team.agents.length}
              </span>
            )}
            <Button
              size="sm"
              variant="ghost"
              className="h-6 w-6 p-0 hover:bg-slate-600"
              onClick={(e) => {
                e.stopPropagation();
                // TODO: Implement team actions menu
                toast({
                  title: "Team Actions",
                  description: "Team management features coming soon",
                });
              }}
            >
              <MoreHorizontal className="w-3 h-3" />
            </Button>
          </div>
        </div>

        {/* Expanded Content */}
        {isExpanded && hasChildren && (
          <div className="mt-1">
            {/* Child Teams */}
            {team.children?.map(childTeam => 
              renderTeamNode(childTeam, depth + 1)
            )}
            
            {/* Agents */}
            {team.agents?.map(agent => (
              <div
                key={agent.id}
                className={cn(
                  "flex items-center space-x-2 p-2 rounded hover:bg-slate-700/30 cursor-pointer transition-colors",
                  "ml-6" + (depth > 0 ? " ml-12" : "")
                )}
                onClick={() => {
                  toast({
                    title: "Agent Selected",
                    description: `Selected ${agent.name} (${agent.type})`,
                  });
                }}
              >
                <div className="w-4 h-4" />
                <Bot className={getStatusColor(agent.status)} />
                <div className="flex-1 flex items-center space-x-2">
                  <span className="text-sm text-white">{agent.name}</span>
                  <span className="text-xs text-slate-400">
                    {getAgentTypeIcon(agent.type)} {agent.type}
                  </span>
                </div>
                <div className={cn(
                  "w-2 h-2 rounded-full",
                  agent.status === 'active' ? 'bg-green-400' :
                  agent.status === 'busy' ? 'bg-amber-400 animate-pulse' :
                  'bg-slate-400'
                )} />
              </div>
            ))}
            
            {/* Add Agent Button */}
            <div className={cn(
              "flex items-center space-x-2 p-2 rounded hover:bg-slate-700/30 cursor-pointer transition-colors text-slate-400 hover:text-slate-300",
              "ml-6" + (depth > 0 ? " ml-12" : "")
            )}
            onClick={() => {
              toast({
                title: "Add Agent",
                description: `Add new agent to ${team.name}`,
              });
            }}>
              <div className="w-4 h-4" />
              <Plus className="w-4 h-4" />
              <span className="text-sm">Add Agent</span>
            </div>
          </div>
        )}
      </div>
    );
  };

  if (!teams.length) {
    return (
      <div className="text-center py-8">
        <Users className="w-12 h-12 text-slate-400 mx-auto mb-4" />
        <p className="text-slate-400 mb-2">No teams configured</p>
        <p className="text-sm text-slate-500 mb-4">Create your first team to organize agents</p>
        <Button size="sm" className="btn-primary">
          <Plus className="w-3 h-3 mr-1" />
          Create Team
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {hierarchy.map(team => renderTeamNode(team))}
      
      {/* Add Root Team Button */}
      <div
        className="flex items-center space-x-2 p-2 rounded hover:bg-slate-700/30 cursor-pointer transition-colors text-slate-400 hover:text-slate-300 border-t border-slate-700 mt-4 pt-4"
        onClick={() => {
          toast({
            title: "Add Team",
            description: "Create new root team",
          });
        }}
      >
        <Plus className="w-4 h-4" />
        <Users className="w-4 h-4" />
        <span className="text-sm">Add Team</span>
      </div>
    </div>
  );
}
