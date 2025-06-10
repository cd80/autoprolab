import { Shield, Bell, Settings, User, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface HeaderProps {
  activeHtbLab?: any;
}

export default function Header({ activeHtbLab }: HeaderProps) {
  return (
    <header className="h-16 bg-slate-900 border-b border-slate-700 px-6 flex items-center justify-between">
      {/* Logo and Title */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center">
            <Shield className="text-white text-sm" />
          </div>
          <h1 className="text-xl font-bold text-white">RedTeam Command Center</h1>
        </div>
        
        {activeHtbLab && (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
            {activeHtbLab.name} Active
          </Badge>
        )}
      </div>

      {/* Search and Actions */}
      <div className="flex items-center space-x-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-4 h-4" />
          <Input 
            placeholder="Search targets, agents, tools..." 
            className="pl-10 w-64 bg-slate-800 border-slate-600 text-white placeholder-slate-400"
          />
        </div>

        <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white">
          <Bell className="w-4 h-4" />
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white">
              <User className="w-4 h-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-slate-800 border-slate-700">
            <DropdownMenuItem className="text-white hover:bg-slate-700">
              <Settings className="w-4 h-4 mr-2" />
              Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-slate-700" />
            <DropdownMenuItem className="text-white hover:bg-slate-700">
              Sign Out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}