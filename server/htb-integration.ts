import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec } from 'child_process';

const execAsync = promisify(exec);

export interface HtbLab {
  id: string;
  name: string;
  difficulty: string;
  description: string;
  status: 'available' | 'starting' | 'active' | 'stopping' | 'stopped';
  machines: HtbMachine[];
  network: string;
}

export interface HtbMachine {
  id: string;
  name: string;
  ip: string;
  os: string;
  difficulty: string;
  flags: {
    user: boolean;
    root: boolean;
  };
}

export class HtbOperatorService {
  private htbApiKey: string;
  
  constructor() {
    this.htbApiKey = process.env.HTB_API_KEY || '';
    if (!this.htbApiKey) {
      console.warn('HTB_API_KEY not found in environment variables');
    }
  }

  async getAvailableLabs(): Promise<HtbLab[]> {
    if (!this.htbApiKey) {
      throw new Error('HTB_API_KEY is required but not found in environment variables');
    }

    try {
      await this.ensureInitialized();
      const { stdout } = await execAsync('htb-operator prolabs list', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey },
        timeout: 30000
      });
      
      const labs = this.parseProLabsOutput(stdout);
      if (labs.length === 0) {
        throw new Error('No ProLabs found in HTB API response');
      }
      return labs;
    } catch (error) {
      console.error('Failed to fetch HTB ProLabs:', error);
      
      try {
        console.log('Retrying HTB ProLabs fetch with re-initialization...');
        await this.forceReInitialize();
        const { stdout } = await execAsync('htb-operator prolabs list', {
          env: { ...process.env, HTB_API_KEY: this.htbApiKey },
          timeout: 30000
        });
        
        const labs = this.parseProLabsOutput(stdout);
        if (labs.length === 0) {
          throw new Error('No ProLabs found in HTB API response after retry');
        }
        return labs;
      } catch (retryError) {
        console.error('Retry failed:', retryError);
        throw new Error(`Failed to fetch HTB ProLabs: ${error}. Retry also failed: ${retryError}`);
      }
    }
  }

  async startLab(labName: string): Promise<{ success: boolean; message: string; lab?: HtbLab }> {
    try {
      await this.ensureInitialized();
      
      await this.startVpnConnection();
      
      const lab = await this.getLabDetails(labName);
      
      return {
        success: true,
        message: `ProLab ${labName} VPN connection established successfully`,
        lab
      };
    } catch (error) {
      console.error('Failed to start HTB ProLab:', error);
      return {
        success: false,
        message: `Error starting ProLab: ${error}`
      };
    }
  }

  async stopLab(): Promise<{ success: boolean; message: string }> {
    try {
      await this.ensureInitialized();
      
      const { stdout } = await execAsync('htb-operator vpn stop', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey }
      });
      
      return {
        success: true,
        message: 'ProLab VPN connection stopped successfully'
      };
    } catch (error) {
      console.error('Failed to stop HTB ProLab VPN:', error);
      return {
        success: false,
        message: `Error stopping ProLab VPN: ${error}`
      };
    }
  }

  async getActiveLab(): Promise<HtbLab | null> {
    if (!this.htbApiKey) {
      throw new Error('HTB_API_KEY is required but not found in environment variables');
    }

    try {
      await this.ensureInitialized();
      
      const { stdout } = await execAsync('htb-operator vpn status', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey },
        timeout: 15000
      });
      
      if (stdout.includes('Connected') || stdout.includes('Active')) {
        const labNameMatch = stdout.match(/Connected to (.+?) ProLab/i) || 
                           stdout.match(/Active ProLab: (.+)/i);
        
        if (labNameMatch) {
          const labName = labNameMatch[1].trim();
          return await this.getLabDetails(labName);
        } else {
          const labs = await this.getAvailableLabs();
          if (labs.length > 0) {
            return await this.getLabDetails(labs[0].name);
          }
        }
      }
      return null;
    } catch (error) {
      console.error('Failed to get active ProLab:', error);
      throw new Error(`Failed to get active ProLab: ${error}`);
    }
  }

  async getLabDetails(labName: string): Promise<HtbLab> {
    if (!this.htbApiKey) {
      throw new Error('HTB_API_KEY is required but not found in environment variables');
    }

    try {
      await this.ensureInitialized();
      const { stdout } = await execAsync(`htb-operator prolabs info --name "${labName}"`, {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey },
        timeout: 20000
      });
      
      const labInfo = this.parseProLabInfo(stdout);
      return labInfo;
    } catch (error) {
      console.error('Failed to get ProLab details:', error);
      
      try {
        console.log(`Retrying with lab ID lookup for: ${labName}`);
        const labs = await this.getAvailableLabs();
        const targetLab = labs.find(lab => 
          lab.name.toLowerCase() === labName.toLowerCase() || 
          lab.id === labName
        );
        
        if (targetLab) {
          const { stdout } = await execAsync(`htb-operator prolabs info --id ${targetLab.id}`, {
            env: { ...process.env, HTB_API_KEY: this.htbApiKey },
            timeout: 20000
          });
          
          const labInfo = this.parseProLabInfo(stdout);
          return labInfo;
        }
      } catch (retryError) {
        console.error('Retry with lab ID also failed:', retryError);
      }
      
      throw new Error(`Failed to get ProLab details for ${labName}: ${error}`);
    }
  }

  async scanLabNetwork(network: string = '10.10.110.0/24'): Promise<any[]> {
    try {
      const { stdout } = await execAsync(`nmap -sn ${network} --format json`, {
        timeout: 30000
      });
      
      const hosts = this.parseNmapOutput(stdout);
      return hosts;
    } catch (error) {
      console.error('Failed to scan lab network:', error);
      return [];
    }
  }

  private async waitForLabStatus(labId: string, expectedStatus: string, maxWaitTime: number = 300000): Promise<void> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      try {
        const lab = await this.getLabDetails(labId);
        if (lab.status === expectedStatus) {
          return;
        }
        
        await new Promise(resolve => setTimeout(resolve, 5000));
      } catch (error) {
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
    
    throw new Error(`Lab ${labId} did not reach status ${expectedStatus} within ${maxWaitTime}ms`);
  }

  private parseNmapOutput(output: string): Array<{ip: string, status: string, hostname: string}> {
    const lines = output.split('\n');
    const hosts: Array<{ip: string, status: string, hostname: string}> = [];
    
    for (const line of lines) {
      if (line.includes('Nmap scan report for')) {
        const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
        if (ipMatch) {
          hosts.push({
            ip: ipMatch[1],
            status: 'up',
            hostname: line.split(' ')[4] || ipMatch[1]
          });
        }
      }
    }
    
    return hosts;
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.htbApiKey) {
      throw new Error('HTB_API_KEY is required for initialization');
    }

    try {
      const { stdout, stderr } = await execAsync('htb-operator init -api $HTB_API_KEY', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey },
        timeout: 15000
      });
      
      if (stderr && stderr.includes('error')) {
        throw new Error(`HTB operator initialization failed: ${stderr}`);
      }
    } catch (error) {
      console.error('HTB operator initialization error:', error);
      throw new Error(`Failed to initialize HTB operator: ${error}`);
    }
  }

  private async forceReInitialize(): Promise<void> {
    if (!this.htbApiKey) {
      throw new Error('HTB_API_KEY is required for re-initialization');
    }

    try {
      await execAsync('htb-operator logout', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey },
        timeout: 10000
      }).catch(() => {}); // Ignore logout errors
      
      const { stdout, stderr } = await execAsync('htb-operator init -api $HTB_API_KEY', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey },
        timeout: 15000
      });
      
      if (stderr && stderr.includes('error')) {
        throw new Error(`HTB operator re-initialization failed: ${stderr}`);
      }
    } catch (error) {
      console.error('HTB operator re-initialization error:', error);
      throw new Error(`Failed to re-initialize HTB operator: ${error}`);
    }
  }

  private async startVpnConnection(): Promise<void> {
    try {
      const { stdout: vpnList } = await execAsync('htb-operator vpn list --prolabs', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey }
      });
      
      await execAsync('htb-operator vpn start --id 309', {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey }
      });
      
      await new Promise(resolve => setTimeout(resolve, 10000));
    } catch (error) {
      console.error('Failed to start VPN connection:', error);
      throw error;
    }
  }

  private parseProLabsOutput(output: string): HtbLab[] {
    const labs: HtbLab[] = [];
    const lines = output.split('\n');
    
    let currentLab: any = {};
    let inLabBlock = false;
    
    for (const line of lines) {
      if (line.includes('─ ') && line.includes(' ─')) {
        if (inLabBlock && currentLab.name) {
          labs.push(this.convertToHtbLab(currentLab));
        }
        
        const nameMatch = line.match(/─ (.+?) ─/);
        if (nameMatch) {
          currentLab = { name: nameMatch[1] };
          inLabBlock = true;
        }
      } else if (inLabBlock && line.includes('│')) {
        const cleanLine = line.replace(/│/g, '').trim();
        
        if (cleanLine.startsWith('ID')) {
          const idMatch = cleanLine.match(/ID\s*:\s*(\d+)/);
          if (idMatch) currentLab.id = idMatch[1];
        } else if (cleanLine.startsWith('# Machines')) {
          const machinesMatch = cleanLine.match(/# Machines\s*:\s*(\d+)/);
          if (machinesMatch) currentLab.machines = parseInt(machinesMatch[1]);
        } else if (cleanLine.startsWith('# Flags')) {
          const flagsMatch = cleanLine.match(/# Flags\s*:\s*(\d+)/);
          if (flagsMatch) currentLab.flags = parseInt(flagsMatch[1]);
        } else if (cleanLine.startsWith('Skill Level')) {
          const difficultyMatch = cleanLine.match(/Skill Level\s*:\s*(.+)/);
          if (difficultyMatch) currentLab.difficulty = difficultyMatch[1].trim();
        } else if (cleanLine.startsWith('Entry Points')) {
          const networkMatch = cleanLine.match(/Entry Points\s*:\s*(.+)/);
          if (networkMatch) currentLab.network = networkMatch[1].trim();
        }
      }
    }
    
    if (inLabBlock && currentLab.name) {
      labs.push(this.convertToHtbLab(currentLab));
    }
    
    return labs;
  }

  private parseProLabInfo(output: string): HtbLab {
    const lines = output.split('\n');
    const labInfo: any = {};
    const machines: HtbMachine[] = [];
    
    for (const line of lines) {
      const cleanLine = line.replace(/[│╭╮╯╰─]/g, '').trim();
      
      if (cleanLine.startsWith('Name') && cleanLine.includes(':')) {
        const nameMatch = cleanLine.match(/Name\s*:\s*(.+)/);
        if (nameMatch) labInfo.name = nameMatch[1].trim();
      } else if (cleanLine.startsWith('ID') && cleanLine.includes(':')) {
        const idMatch = cleanLine.match(/ID\s*:\s*(\d+)/);
        if (idMatch) labInfo.id = idMatch[1];
      } else if (cleanLine.startsWith('# Machines')) {
        const machinesMatch = cleanLine.match(/# Machines\s*:\s*(\d+)/);
        if (machinesMatch) labInfo.machineCount = parseInt(machinesMatch[1]);
      } else if (cleanLine.startsWith('# Flags')) {
        const flagsMatch = cleanLine.match(/# Flags\s*:\s*(\d+)/);
        if (flagsMatch) labInfo.flagCount = parseInt(flagsMatch[1]);
      } else if (cleanLine.startsWith('Difficulty')) {
        const difficultyMatch = cleanLine.match(/Difficulty\s*:\s*(.+)/);
        if (difficultyMatch) labInfo.difficulty = difficultyMatch[1].trim();
      } else if (cleanLine.startsWith('Entry Point')) {
        const networkMatch = cleanLine.match(/Entry Point\(s\)\s*:\s*(.+)/);
        if (networkMatch) labInfo.network = networkMatch[1].trim();
      }
      
      if (cleanLine.includes('APT-') || cleanLine.includes('🐧') || cleanLine.includes('🗔') || cleanLine.includes('Windows') || cleanLine.includes('Linux')) {
        const parts = cleanLine.split(/\s+/);
        if (parts.length >= 2) {
          const machineName = parts.find(part => part.includes('APT-') || part.match(/^[A-Z]+-[A-Z0-9]+$/));
          if (machineName) {
            const os = cleanLine.includes('🐧') ? 
              (cleanLine.includes('FreeBSD') ? 'FreeBSD' : 'Linux') : 
              (cleanLine.includes('🗔') || cleanLine.includes('Windows') ? 'Windows' : 'Unknown');
            
            const ipMatch = cleanLine.match(/(\d+\.\d+\.\d+\.\d+)/);
            const machineIp = ipMatch ? ipMatch[1] : `10.10.110.${machines.length + 100}`;
            
            machines.push({
              id: machineName.toLowerCase(),
              name: machineName,
              ip: machineIp,
              os: os,
              difficulty: labInfo.difficulty || 'Expert',
              flags: { user: false, root: false }
            });
          }
        }
      }
    }
    
    if (!labInfo.name) {
      throw new Error('Lab name not found in HTB API response');
    }
    
    return {
      id: labInfo.id || labInfo.name.toLowerCase().replace(/\s+/g, '-'),
      name: labInfo.name,
      difficulty: labInfo.difficulty || 'Unknown',
      description: `${labInfo.name} ProLab with ${labInfo.machineCount || machines.length} machines and ${labInfo.flagCount || 0} flags`,
      status: 'available',
      machines: machines,
      network: labInfo.network || '10.10.110.0/24'
    };
  }

  private convertToHtbLab(labData: any): HtbLab {
    return {
      id: labData.id || labData.name.toLowerCase(),
      name: labData.name,
      difficulty: labData.difficulty || 'Unknown',
      description: `ProLab with ${labData.machines || 0} machines and ${labData.flags || 0} flags`,
      status: 'available',
      machines: [],
      network: labData.network || '10.10.110.0/24'
    };
  }

  async submitFlag(labName: string, flag: string): Promise<{ success: boolean; message: string }> {
    try {
      await this.ensureInitialized();
      const { stdout } = await execAsync(`htb-operator prolabs submit --name "${labName}" --flag '${flag}'`, {
        env: { ...process.env, HTB_API_KEY: this.htbApiKey }
      });
      
      return {
        success: true,
        message: `Flag submitted successfully for ${labName}`
      };
    } catch (error) {
      console.error('Failed to submit flag:', error);
      return {
        success: false,
        message: `Error submitting flag: ${error}`
      };
    }
  }


}

export const htbOperator = new HtbOperatorService();
