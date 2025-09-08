import { applyDecorators, UseGuards } from '@nestjs/common';
import { ApiSecurity, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from './roles.decorator';
import { Role } from '../enums/role.enum';

/**
 * @Auth() Decorator - Enterprise Authentication & Authorization
 * 
 * Combines authentication, authorization, and API documentation in one decorator.
 * This is a "composed decorator" that applies multiple decorators at once.
 * 
 * Framework Mental Applied:
 * - DRY: Don't repeat authentication + authorization boilerplate
 * - Consistency: Same security patterns across all protected endpoints
 * - Developer Experience: Simple API, complex implementation hidden
 * - Documentation: Automatic Swagger docs for security
 * 
 * @param roles Optional roles required to access the endpoint
 * 
 * @example
 * ```typescript
 * // Public endpoint (no auth required)
 * @Get('public')
 * publicEndpoint() { ... }
 * 
 * // User authentication required
 * @Auth()
 * @Get('user-only') 
 * userEndpoint() { ... }
 * 
 * // Admin authorization required
 * @Auth(Role.ADMIN)
 * @Get('admin-only')
 * adminEndpoint() { ... }
 * ```
 */
export function Auth(...roles: Role[]) {
  const decorators = [
    // Framework Mental: Authentication first - verify user identity
    UseGuards(JwtAuthGuard),
    
    // Framework Mental: API Documentation - auto-generate security docs
    ApiBearerAuth(), // Swagger: shows "Authorize" button
    ApiSecurity('bearer'), // Swagger: bearer token required
    
    // Framework Mental: Standard error responses for all auth endpoints  
    ApiResponse({
      status: 401,
      description: 'Authentication failed - invalid or missing token'
    }),
  ];

  // Framework Mental: Authorization (if roles specified)
  if (roles.length > 0) {
    decorators.push(
      // Add RolesGuard for authorization
      UseGuards(RolesGuard), // Note: JwtAuthGuard runs first, then RolesGuard
      
      // Set required roles metadata
      Roles(...roles),
      
      // Additional Swagger documentation
      ApiResponse({
        status: 403, 
        description: 'Authorization failed - insufficient privileges'
      })
    );
  }

  // Framework Mental: Decorator composition - apply all decorators at once
  return applyDecorators(...decorators);
}

/**
 * Type-safe Auth decorator variants for common use cases
 * These provide better IntelliSense and prevent role mistakes
 */

/**
 * @AuthAdmin - Shortcut for admin-only endpoints
 * Equivalent to @Auth(Role.ADMIN)
 */
export const AuthAdmin = () => Auth(Role.ADMIN);

/**
 * @AuthUser - Shortcut for user authentication (no specific role required)
 * Equivalent to @Auth()
 */
export const AuthUser = () => Auth();

/**
 * Usage Examples:
 * 
 * @AuthUser()           // Any authenticated user
 * @AuthAdmin()          // Admin only
 * @Auth(Role.ADMIN)     // Admin only (explicit)
 * @Auth(Role.USER)      // User role (usually unnecessary since USER is default)
 */