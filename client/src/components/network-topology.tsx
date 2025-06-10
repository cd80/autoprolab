import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RotateCcw, Download } from "lucide-react";
import type { NetworkNode, NetworkLink } from "@shared/schema";

export default function NetworkTopology() {
  const svgRef = useRef<SVGSVGElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 });
  const queryClient = useQueryClient();

  const { data: topology, isLoading } = useQuery<{ nodes: NetworkNode[], links: NetworkLink[] }>({
    queryKey: ["/api/network-topology"],
  });

  const updateTopologyMutation = useMutation({
    mutationFn: async (data: { nodes: NetworkNode[], links: NetworkLink[] }) => {
      const response = await fetch("/api/network-topology", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error("Failed to update topology");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/network-topology"] });
    },
  });

  useEffect(() => {
    const updateDimensions = () => {
      const container = svgRef.current?.parentElement;
      if (container) {
        setDimensions({
          width: container.clientWidth,
          height: 400,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  useEffect(() => {
    if (!topology || !svgRef.current) return;

    const svg = svgRef.current;
    const { width, height } = dimensions;

    // Clear existing content
    while (svg.firstChild) {
      svg.removeChild(svg.firstChild);
    }

    const colorMap = {
      'attacker': '#0ea5e9',
      'infrastructure': '#6b7280',
      'compromised': '#10b981',
      'in-progress': '#f59e0b',
      'target': '#ef4444'
    };

    // Create links
    topology.links.forEach(link => {
      const sourceNode = topology.nodes.find(n => n.id === link.source);
      const targetNode = topology.nodes.find(n => n.id === link.target);
      
      if (sourceNode && targetNode) {
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", String(sourceNode.x || 0));
        line.setAttribute("y1", String(sourceNode.y || 0));
        line.setAttribute("x2", String(targetNode.x || 0));
        line.setAttribute("y2", String(targetNode.y || 0));
        line.setAttribute("stroke", "#4b5563");
        line.setAttribute("stroke-width", "2");
        svg.appendChild(line);
      }
    });

    // Create nodes
    topology.nodes.forEach(node => {
      const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
      group.setAttribute("transform", `translate(${node.x || 0}, ${node.y || 0})`);
      group.style.cursor = "pointer";

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("r", "20");
      circle.setAttribute("fill", colorMap[node.type]);
      circle.setAttribute("stroke", "#374151");
      circle.setAttribute("stroke-width", "2");

      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("dy", "4");
      text.setAttribute("fill", "#f8fafc");
      text.setAttribute("font-size", "10");
      text.textContent = node.name;

      group.appendChild(circle);
      group.appendChild(text);

      // Add drag functionality
      let isDragging = false;
      let startX = 0;
      let startY = 0;

      group.addEventListener("mousedown", (e) => {
        isDragging = true;
        startX = e.clientX - (node.x || 0);
        startY = e.clientY - (node.y || 0);
        group.style.cursor = "grabbing";
      });

      svg.addEventListener("mousemove", (e) => {
        if (!isDragging) return;
        
        const newX = e.clientX - startX;
        const newY = e.clientY - startY;
        
        // Update node position
        node.x = Math.max(20, Math.min(width - 20, newX));
        node.y = Math.max(20, Math.min(height - 20, newY));
        
        group.setAttribute("transform", `translate(${node.x}, ${node.y})`);
        
        // Update connected links
        topology.links.forEach(link => {
          if (link.source === node.id || link.target === node.id) {
            const sourceNode = topology.nodes.find(n => n.id === link.source);
            const targetNode = topology.nodes.find(n => n.id === link.target);
            
            if (sourceNode && targetNode) {
              const lines = svg.querySelectorAll("line");
              lines.forEach(line => {
                if (
                  (line.getAttribute("x1") === String(sourceNode.x) && 
                   line.getAttribute("y1") === String(sourceNode.y)) ||
                  (line.getAttribute("x2") === String(targetNode.x) && 
                   line.getAttribute("y2") === String(targetNode.y))
                ) {
                  line.setAttribute("x1", String(sourceNode.x));
                  line.setAttribute("y1", String(sourceNode.y));
                  line.setAttribute("x2", String(targetNode.x));
                  line.setAttribute("y2", String(targetNode.y));
                }
              });
            }
          }
        });
      });

      svg.addEventListener("mouseup", () => {
        if (isDragging) {
          isDragging = false;
          group.style.cursor = "pointer";
          
          // Save the updated topology
          updateTopologyMutation.mutate(topology);
        }
      });

      svg.appendChild(group);
    });

  }, [topology, dimensions, updateTopologyMutation]);

  const resetView = () => {
    if (topology) {
      const resetTopology = {
        nodes: topology.nodes.map((node, index) => ({
          ...node,
          x: 100 + (index % 3) * 200,
          y: 100 + Math.floor(index / 3) * 150,
        })),
        links: topology.links,
      };
      updateTopologyMutation.mutate(resetTopology);
    }
  };

  const exportTopology = () => {
    if (!svgRef.current) return;
    
    const svgData = new XMLSerializer().serializeToString(svgRef.current);
    const blob = new Blob([svgData], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "network-topology.svg";
    link.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex items-center justify-center h-96">
            <div className="text-slate-400">Loading network topology...</div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6">
      <Card className="h-full">
        <CardHeader>
          <CardTitle>Network Topology</CardTitle>
          <div className="flex space-x-2">
            <Button size="sm" variant="secondary" onClick={resetView}>
              <RotateCcw className="w-3 h-3" />
              Reset View
            </Button>
            <Button size="sm" variant="secondary" onClick={exportTopology}>
              <Download className="w-3 h-3" />
              Export
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="relative w-full h-96 bg-slate-800/30 rounded-lg overflow-hidden">
            <svg
              ref={svgRef}
              width={dimensions.width}
              height={dimensions.height}
              className="w-full h-full"
            />
            
            {/* Legend */}
            <div className="absolute top-4 right-4 space-y-2">
              <div className="flex items-center space-x-2 text-xs">
                <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                <span className="text-slate-300">Compromised</span>
              </div>
              <div className="flex items-center space-x-2 text-xs">
                <div className="w-3 h-3 bg-amber-400 rounded-full"></div>
                <span className="text-slate-300">In Progress</span>
              </div>
              <div className="flex items-center space-x-2 text-xs">
                <div className="w-3 h-3 bg-red-400 rounded-full"></div>
                <span className="text-slate-300">Target</span>
              </div>
              <div className="flex items-center space-x-2 text-xs">
                <div className="w-3 h-3 bg-slate-400 rounded-full"></div>
                <span className="text-slate-300">Infrastructure</span>
              </div>
              <div className="flex items-center space-x-2 text-xs">
                <div className="w-3 h-3 bg-blue-400 rounded-full"></div>
                <span className="text-slate-300">Attacker</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
