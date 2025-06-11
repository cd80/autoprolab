"""
APTLabs-specific agent configuration and deployment
"""
import asyncio
import logging
from typing import Dict, List, Any
from agents.aptlabs_operation import AptlabsOperationAgent
from agents.htb_aptlabs_agent import HtbAptlabsAgent
from agents.network_scanner_agent import NetworkScannerAgent
from agents.recon_agent import ReconAgent
from agents.initial_access_agent import InitialAccessAgent

class AptlabsAgentDeployer:
    """
    Deploys and manages agents specifically for APTLabs Pro Lab operations.
    Coordinates autonomous flag capture through specialized cybersecurity agents.
    """
    
    def __init__(self):
        self.agents = {}
        self.logger = logging.getLogger(__name__)
        self.aptlabs_network = "10.10.110.0/24"
        self.target_lab = "APTLabs"
        
    async def deploy_aptlabs_agents(self) -> Dict[str, Any]:
        """Deploy agents specifically for APTLabs operation"""
        try:
            self.logger.info("Deploying APTLabs-specific agent configuration...")
            
            self.agents = {
                'operation': AptlabsOperationAgent(),
                'htb': HtbAptlabsAgent(), 
                'scanner': NetworkScannerAgent(),
                'recon': ReconAgent(),
                'access': InitialAccessAgent()
            }
            
            await self._configure_agents_for_aptlabs()
            
            operation_result = await self.agents['operation'].initialize_operation({
                'target_lab': self.target_lab,
                'network_range': self.aptlabs_network,
                'agents': self.agents
            })
            
            self.logger.info("APTLabs agents deployed successfully")
            return {
                'success': True,
                'agents_deployed': list(self.agents.keys()),
                'operation_status': operation_result
            }
            
        except Exception as e:
            self.logger.error(f"Failed to deploy APTLabs agents: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _configure_agents_for_aptlabs(self):
        """Configure agents with APTLabs-specific parameters"""
        
        if 'htb' in self.agents:
            await self.agents['htb'].configure({
                'lab_name': self.target_lab,
                'lab_id': '5',
                'network': self.aptlabs_network
            })
        
        if 'scanner' in self.agents:
            await self.agents['scanner'].configure({
                'target_network': self.aptlabs_network,
                'scan_intensity': 'comprehensive'
            })
        
        if 'recon' in self.agents:
            await self.agents['recon'].configure({
                'target_environment': 'aptlabs',
                'enumeration_depth': 'deep'
            })
            
        if 'access' in self.agents:
            await self.agents['access'].configure({
                'target_lab': self.target_lab,
                'attack_vectors': ['web', 'smb', 'rdp', 'ssh']
            })
        
    async def execute_flag_capture(self) -> Dict[str, Any]:
        """Execute autonomous flag capture on APTLabs"""
        try:
            if 'operation' not in self.agents:
                deploy_result = await self.deploy_aptlabs_agents()
                if not deploy_result['success']:
                    return deploy_result
            
            self.logger.info("Starting autonomous flag capture operation on APTLabs...")
            
            attack_result = await self.agents['operation'].execute_full_attack_chain()
            
            return {
                'success': True,
                'operation': 'flag_capture',
                'target_lab': self.target_lab,
                'results': attack_result
            }
            
        except Exception as e:
            self.logger.error(f"Flag capture operation failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_operation_status(self) -> Dict[str, Any]:
        """Get current status of APTLabs operation"""
        if 'operation' not in self.agents:
            return {'status': 'not_deployed'}
            
        try:
            status = await self.agents['operation'].get_status()
            return {
                'status': 'active',
                'agents': {name: 'active' for name in self.agents.keys()},
                'operation_details': status
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def stop_operation(self) -> Dict[str, Any]:
        """Stop APTLabs operation and cleanup"""
        try:
            if 'operation' in self.agents:
                await self.agents['operation'].cleanup()
            
            self.agents.clear()
            
            return {
                'success': True,
                'message': 'APTLabs operation stopped successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

async def main():
    """Main function for testing APTLabs agent deployment"""
    deployer = AptlabsAgentDeployer()
    
    deploy_result = await deployer.deploy_aptlabs_agents()
    print(f"Deployment result: {deploy_result}")
    
    if deploy_result['success']:
        capture_result = await deployer.execute_flag_capture()
        print(f"Flag capture result: {capture_result}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
