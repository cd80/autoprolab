# RedTeam Command Center

A comprehensive Red Teaming dashboard for managing AI agents, visualizing network topologies, and tracking Hack The Box Pro Lab progress using React and Express.js with PostgreSQL.

## Features

### 🤖 Agent Management
- Create and deploy AI-powered red team agents
- Hierarchical team organization
- Real-time agent status monitoring
- Custom agent instructions and tool assignments

### 🎯 Target Analysis
- Comprehensive target reconnaissance
- Network topology visualization
- Vulnerability assessment tracking
- Interactive target detail views with exploitation actions

### 🛠️ Tool Registry
- MCP (Model Context Protocol) server integration
- Custom tool development and deployment
- Tool status monitoring and management
- Extensible tool framework

### 🏴 HTB Pro Lab Integration
- Hack The Box htb-operator integration
- Pro Lab selection and management
- Real-time flag capture tracking
- Progress visualization and statistics

### 🌐 Active Directory Visualization
- Comprehensive AD environment mapping
- User, group, and computer visualization
- Trust relationship analysis
- Domain controller monitoring

### 📊 Dashboard & Analytics
- Real-time operational metrics
- Activity timeline and logging
- System status monitoring
- Professional command center interface

## Technology Stack

### Frontend
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **shadcn/ui** component library
- **TanStack Query** for data fetching
- **Lucide React** for icons
- **Wouter** for routing

### Backend
- **Node.js** with Express.js
- **TypeScript** for type safety
- **PostgreSQL** with Drizzle ORM
- **Zod** for validation
- **RESTful API** architecture

### Infrastructure
- **PostgreSQL** database
- **Vite** development server
- **Hot module replacement**
- **Environment-based configuration**

## Quick Start

### Prerequisites
- Node.js 18+
- PostgreSQL database
- Modern web browser

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd redteam-command-center
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   # Database configuration is automatically handled by Replit
   # For local development, set DATABASE_URL
   export DATABASE_URL="postgresql://user:password@localhost:5432/redteam"
   ```

4. **Initialize the database**
   ```bash
   npm run db:push
   ```

5. **Start the application**
   ```bash
   npm run dev
   ```

6. **Access the dashboard**
   Open your browser to `http://localhost:5000`

## Project Structure

```
├── client/                 # Frontend React application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   │   ├── layout/     # Layout components (Header, StatusBar)
│   │   │   └── ui/         # shadcn/ui components
│   │   ├── pages/          # Page components
│   │   ├── hooks/          # Custom React hooks
│   │   └── lib/            # Utilities and configurations
├── server/                 # Backend Express application
│   ├── db.ts              # Database connection
│   ├── routes.ts          # API routes
│   ├── storage.ts         # Data access layer
│   └── seed.ts            # Database seeding
├── shared/                 # Shared types and schemas
│   └── schema.ts          # Drizzle database schema
└── README.md              # This file
```

## API Endpoints

### Agents
- `GET /api/agents` - List all agents
- `POST /api/agents` - Create new agent
- `PATCH /api/agents/:id` - Update agent
- `DELETE /api/agents/:id` - Delete agent

### Targets
- `GET /api/targets` - List all targets
- `POST /api/targets` - Create new target
- `PATCH /api/targets/:id` - Update target
- `DELETE /api/targets/:id` - Delete target
- `POST /api/targets/:id/actions/:action` - Execute action on target

### HTB Integration
- `GET /api/htb-operator/labs` - List available Pro Labs
- `POST /api/htb-operator/labs/:labId/start` - Start Pro Lab
- `POST /api/htb-operator/labs/stop` - Stop active Pro Lab
- `GET /api/htb-labs/active` - Get active lab status

### Tools
- `GET /api/mcp-servers` - List MCP servers
- `POST /api/mcp-servers` - Add MCP server
- `GET /api/custom-tools` - List custom tools
- `POST /api/custom-tools` - Create custom tool

### Analytics
- `GET /api/dashboard/metrics` - Get dashboard metrics
- `GET /api/activities` - List recent activities
- `GET /api/network-topology` - Get network topology data

## Database Schema

The application uses PostgreSQL with the following main tables:

- **agents** - AI agent configurations and status
- **teams** - Hierarchical team organization
- **targets** - Target systems and reconnaissance data
- **mcp_servers** - MCP server configurations
- **custom_tools** - Custom tool definitions
- **htb_labs** - HTB Pro Lab tracking
- **activities** - System activity logs

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run db:push` - Push schema changes to database
- `npm run db:studio` - Open Drizzle Studio

### Environment Variables

- `DATABASE_URL` - PostgreSQL connection string
- `NODE_ENV` - Environment (development/production)
- `PORT` - Server port (default: 5000)

## HTB Operator Integration

The dashboard integrates with htb-operator for Pro Lab management:

1. **Lab Selection** - Browse and select available Pro Labs
2. **Lab Control** - Start/stop lab instances
3. **Progress Tracking** - Monitor flag capture progress
4. **Network Mapping** - Visualize lab network topology

## Security Considerations

- All API endpoints include proper validation
- Database queries use parameterized statements
- Environment variables for sensitive configuration
- CORS and security headers configured
- Input sanitization and validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For questions and support, please open an issue in the repository.

---

**RedTeam Command Center** - Professional Red Teaming Dashboard for Modern Penetration Testing Operations