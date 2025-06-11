import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { 
  Users, 
  Shield, 
  Server, 
  Search, 
  ChevronDown, 
  ChevronRight,
  Crown,
  Key,
  AlertTriangle,
  Eye,
  Network
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ADUser {
  id: string;
  username: string;
  displayName: string;
  email: string;
  lastLogon: string;
  enabled: boolean;
  memberOf: string[];
  adminCount?: number;
  description?: string;
}

interface ADGroup {
  id: string;
  name: string;
  type: "Security" | "Distribution";
  scope: "DomainLocal" | "Global" | "Universal";
  members: string[];
  description?: string;
  privileged: boolean;
}

interface ADComputer {
  id: string;
  name: string;
  operatingSystem: string;
  lastLogon: string;
  enabled: boolean;
  servicePrincipalNames: string[];
  description?: string;
}

interface ADDomain {
  name: string;
  netbiosName: string;
  domainControllers: string[];
  trusts: ADTrust[];
  functionalLevel: string;
}

interface ADTrust {
  targetDomain: string;
  trustType: "External" | "Forest" | "Realm" | "Unknown";
  trustDirection: "Inbound" | "Outbound" | "Bidirectional";
}

export default function ADVisualization() {
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [selectedTab, setSelectedTab] = useState("overview");

  const [adDomain, setAdDomain] = useState<ADDomain | null>(null);

  const [adUsers, setAdUsers] = useState<ADUser[]>([]);

  const [adGroups, setAdGroups] = useState<ADGroup[]>([]);

  const [adComputers, setAdComputers] = useState<ADComputer[]>([]);

  useEffect(() => {
    fetchADData();
  }, []);

  const fetchADData = async () => {
    try {
    } catch (error) {
      console.error('Failed to fetch AD data:', error);
    }
  };

  const toggleGroup = (groupId: string) => {
    setExpandedGroups(prev => {
      const newSet = new Set(prev);
      if (newSet.has(groupId)) {
        newSet.delete(groupId);
      } else {
        newSet.add(groupId);
      }
      return newSet;
    });
  };

  const getStatusBadge = (enabled: boolean) => (
    <Badge variant={enabled ? "default" : "destructive"} className="text-xs">
      {enabled ? "Enabled" : "Disabled"}
    </Badge>
  );

  const getPrivilegedBadge = (privileged: boolean) => (
    privileged ? (
      <Badge variant="destructive" className="text-xs">
        <Crown className="w-3 h-3 mr-1" />
        Privileged
      </Badge>
    ) : null
  );

  const formatLastLogon = (lastLogon: string) => {
    const date = new Date(lastLogon);
    const now = new Date();
    const diffHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffHours < 24) {
      return `${diffHours}h ago`;
    } else {
      return `${Math.floor(diffHours / 24)}d ago`;
    }
  };

  const filteredUsers = adUsers.filter(user =>
    user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.displayName.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredGroups = adGroups.filter(group =>
    group.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredComputers = adComputers.filter(computer =>
    computer.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* AD Domain Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Network className="w-5 h-5" />
            <span>Active Directory Overview</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {adDomain ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400">{adDomain.name}</div>
                <div className="text-sm text-slate-400">Domain</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">{adDomain.domainControllers.length}</div>
                <div className="text-sm text-slate-400">Domain Controllers</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-amber-400">{adDomain.functionalLevel}</div>
                <div className="text-sm text-slate-400">Functional Level</div>
              </div>
            </div>
          ) : (
            <div className="text-center text-slate-400 py-8">
              <div className="text-lg">No Active Directory data available</div>
              <div className="text-sm">AD enumeration will be performed by reconnaissance agents</div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Search */}
      <Card>
        <CardContent className="pt-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-4 h-4" />
            <Input
              placeholder="Search users, groups, computers..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 bg-slate-800 border-slate-600 text-white"
            />
          </div>
        </CardContent>
      </Card>

      {/* AD Objects Tabs */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-4 bg-slate-800">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="groups">Groups</TabsTrigger>
          <TabsTrigger value="computers">Computers</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold text-white">{adUsers.length}</div>
                    <div className="text-sm text-slate-400">Total Users</div>
                  </div>
                  <Users className="w-8 h-8 text-blue-400" />
                </div>
                <div className="mt-2">
                  <div className="text-xs text-slate-500">
                    {adUsers.filter(u => u.adminCount).length} privileged accounts
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold text-white">{adGroups.length}</div>
                    <div className="text-sm text-slate-400">Security Groups</div>
                  </div>
                  <Shield className="w-8 h-8 text-green-400" />
                </div>
                <div className="mt-2">
                  <div className="text-xs text-slate-500">
                    {adGroups.filter(g => g.privileged).length} privileged groups
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold text-white">{adComputers.length}</div>
                    <div className="text-sm text-slate-400">Computers</div>
                  </div>
                  <Server className="w-8 h-8 text-purple-400" />
                </div>
                <div className="mt-2">
                  <div className="text-xs text-slate-500">
                    {adComputers.filter(c => c.enabled).length} enabled
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="users" className="space-y-4">
          {filteredUsers.map((user) => (
            <Card key={user.id}>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className={cn(
                      "w-10 h-10 rounded-full flex items-center justify-center",
                      user.adminCount ? "bg-red-500/20" : "bg-blue-500/20"
                    )}>
                      {user.adminCount ? (
                        <Crown className="w-5 h-5 text-red-400" />
                      ) : (
                        <Users className="w-5 h-5 text-blue-400" />
                      )}
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{user.displayName}</h3>
                      <p className="text-sm text-slate-400">{user.username}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {user.adminCount && getPrivilegedBadge(true)}
                    {getStatusBadge(user.enabled)}
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-slate-400">Email:</span>
                    <span className="text-white ml-2">{user.email}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Last Logon:</span>
                    <span className="text-white ml-2">{formatLastLogon(user.lastLogon)}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Groups:</span>
                    <span className="text-white ml-2">{user.memberOf.length}</span>
                  </div>
                </div>

                {user.memberOf.length > 0 && (
                  <div className="mt-4">
                    <div className="text-sm text-slate-400 mb-2">Group Memberships:</div>
                    <div className="flex flex-wrap gap-2">
                      {user.memberOf.map((group, idx) => (
                        <Badge 
                          key={idx}
                          variant={adGroups.find(g => g.name === group)?.privileged ? "destructive" : "secondary"}
                          className="text-xs"
                        >
                          {group}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="groups" className="space-y-4">
          {filteredGroups.map((group) => (
            <Card key={group.id}>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className={cn(
                      "w-10 h-10 rounded-full flex items-center justify-center",
                      group.privileged ? "bg-red-500/20" : "bg-green-500/20"
                    )}>
                      <Shield className={cn(
                        "w-5 h-5",
                        group.privileged ? "text-red-400" : "text-green-400"
                      )} />
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{group.name}</h3>
                      <p className="text-sm text-slate-400">{group.type} • {group.scope}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {getPrivilegedBadge(group.privileged)}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => toggleGroup(group.id)}
                      className="text-slate-400 hover:text-white"
                    >
                      {expandedGroups.has(group.id) ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm mb-4">
                  <div>
                    <span className="text-slate-400">Members:</span>
                    <span className="text-white ml-2">{group.members.length}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Type:</span>
                    <span className="text-white ml-2">{group.type}</span>
                  </div>
                </div>

                {group.description && (
                  <div className="text-sm text-slate-300 mb-4">
                    {group.description}
                  </div>
                )}

                {expandedGroups.has(group.id) && group.members.length > 0 && (
                  <div>
                    <div className="text-sm text-slate-400 mb-2">Members:</div>
                    <div className="space-y-2">
                      {group.members.map((member, idx) => {
                        const user = adUsers.find(u => u.username === member);
                        return (
                          <div key={idx} className="flex items-center space-x-2 text-sm">
                            <Users className="w-4 h-4 text-slate-400" />
                            <span className="text-white">{user?.displayName || member}</span>
                            <span className="text-slate-400">({member})</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="computers" className="space-y-4">
          {filteredComputers.map((computer) => (
            <Card key={computer.id}>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-purple-500/20 rounded-full flex items-center justify-center">
                      <Server className="w-5 h-5 text-purple-400" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{computer.name}</h3>
                      <p className="text-sm text-slate-400">{computer.operatingSystem}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {getStatusBadge(computer.enabled)}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-slate-400">Last Logon:</span>
                    <span className="text-white ml-2">{formatLastLogon(computer.lastLogon)}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">SPNs:</span>
                    <span className="text-white ml-2">{computer.servicePrincipalNames.length}</span>
                  </div>
                </div>

                {computer.servicePrincipalNames.length > 0 && (
                  <div className="mt-4">
                    <div className="text-sm text-slate-400 mb-2">Service Principal Names:</div>
                    <div className="flex flex-wrap gap-2">
                      {computer.servicePrincipalNames.map((spn, idx) => (
                        <Badge key={idx} variant="outline" className="text-xs">
                          {spn}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {computer.description && (
                  <div className="mt-4 text-sm text-slate-300">
                    {computer.description}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}
