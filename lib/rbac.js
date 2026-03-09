/**
 * RBAC — Role-Based Access Control
 * Roles: admin, editor, viewer
 *
 * admin  — full access (terminal, secrets, deploy, destructive ops, user management)
 * editor — can modify app state and use AI helpers, but not arbitrary shell/secrets/destructive ops
 * viewer — read-only access to all views, no terminal, no destructive ops
 */

const ROLES = {
  admin: {
    level: 3,
    description: 'Full access to everything',
  },
  editor: {
    level: 2,
    description: 'Can modify app state and use AI, but not secrets or shell-level ops',
  },
  viewer: {
    level: 1,
    description: 'Read-only access to all views',
  },
};

// Actions mapped to minimum role level
const ACTION_PERMISSIONS = {
  // Read-only (viewer+)
  'view:dashboard': 1,
  'view:metrics': 1,
  'view:uptime': 1,
  'view:servers': 1,
  'view:docker': 1,
  'view:db': 1,
  'view:security': 1,
  'view:logs': 1,
  'view:settings': 1,

  // Write operations (editor+)
  'db:query': 2,
  'db:backup': 3,
  'db:restore': 3,
  'db:migration': 3,
  'docker:start': 2,
  'docker:stop': 2,
  'docker:restart': 2,
  'git:commit': 2,
  'git:push': 2,
  'deploy:run': 3,
  'cron:create': 3,
  'cron:delete': 3,
  'files:write': 2,
  'files:delete': 2,
  'envvars:set': 2,
  'envvars:delete': 2,
  'security:scan': 2,
  'ssl:renew': 2,
  'ai:query': 2,
  'tickets:create': 2,
  'tickets:update': 2,
  'calendar:create': 2,
  'credentials:write': 3,
  'notifications:send': 2,

  // Admin-only
  'terminal:access': 3,
  'users:manage': 3,
  'users:create': 3,
  'users:delete': 3,
  'settings:write': 3,
  'db:ddl': 3,
  'docker:remove': 3,
  'ai:settings': 3,
};

function getRoleLevel(role) {
  return (ROLES[role] || ROLES.viewer).level;
}

function hasPermission(userRole, action) {
  const userLevel = getRoleLevel(userRole);
  const requiredLevel = ACTION_PERMISSIONS[action];
  if (requiredLevel === undefined) return userLevel >= 2; // default: editor+
  return userLevel >= requiredLevel;
}

/**
 * Express middleware: require minimum role
 * Usage: app.post('/api/deploy', requireRole('editor'), handler)
 */
function requireRole(minRole) {
  const minLevel = getRoleLevel(minRole);
  return function (req, res, next) {
    const userLevel = getRoleLevel(req.user?.role);
    if (userLevel >= minLevel) return next();
    res.status(403).json({ error: `Requires ${minRole} role or higher` });
  };
}

/**
 * Express middleware: require specific action permission
 * Usage: app.post('/api/deploy/run', requireAction('deploy:run'), handler)
 */
function requireAction(action) {
  return function (req, res, next) {
    if (hasPermission(req.user?.role, action)) return next();
    res.status(403).json({ error: `Permission denied: ${action}` });
  };
}

module.exports = {
  ROLES,
  ACTION_PERMISSIONS,
  getRoleLevel,
  hasPermission,
  requireRole,
  requireAction,
};
