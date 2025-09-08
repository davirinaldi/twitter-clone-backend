/**
 * Simple role-based authorization system
 * Start simple, evolve to permissions when needed
 */
export enum Role {
  USER = 'user',   // Regular users - can tweet, follow, like
  ADMIN = 'admin'  // System administrators - full access
}

/**
 * Role hierarchy for privilege checks
 * ADMIN inherits all USER privileges
 */
export const ROLE_HIERARCHY = [Role.USER, Role.ADMIN] as const;

/**
 * Check if user has required privilege level
 * @param userRole Current user role
 * @param requiredRole Minimum required role  
 * @returns true if user has sufficient privileges
 */
export function hasRequiredRole(userRole: Role, requiredRole: Role): boolean {
  if (requiredRole === Role.USER) {
    return true; // Everyone can access USER-level endpoints
  }
  
  if (requiredRole === Role.ADMIN) {
    return userRole === Role.ADMIN; // Only admins can access ADMIN endpoints
  }
  
  return false;
}