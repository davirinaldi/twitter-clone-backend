import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role, hasRequiredRole } from '../enums/role.enum';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { User } from '../../users/users.entity';

/**
 * RolesGuard - Authorization guard for role-based access control
 * 
 * Usage:
 * 1. Apply after JwtAuthGuard for authentication
 * 2. Use with @Roles() decorator to specify required roles
 * 
 * @example
 * ```typescript
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * @Roles(Role.ADMIN)
 * @Get('admin-only')
 * adminEndpoint() { ... }
 * ```
 * 
 * Framework Mental Applied:
 * - Security-first: Deny by default, explicit allow
 * - Failure-first: Comprehensive error handling and logging
 * - Observability: Structured logging for security audit
 * - Performance: Fast metadata reflection, no database calls
 */
@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    try {
      // Framework Mental: Metadata extraction - get required roles
      const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
        context.getHandler(),     // Method-level @Roles()
        context.getClass(),       // Class-level @Roles()
      ]);

      // Framework Mental: Graceful defaults - no roles = USER access
      if (!requiredRoles || requiredRoles.length === 0) {
        return true; // No specific roles required, allow access
      }

      // Framework Mental: Context extraction - get authenticated user
      const request = context.switchToHttp().getRequest();
      const user: User = request.user;

      // Framework Mental: Security-first - validate user context
      if (!user) {
        this.logger.warn('RolesGuard: No user in request context', {
          handler: context.getHandler().name,
          class: context.getClass().name
        });
        return false;
      }

      // Framework Mental: Authorization logic - check user roles
      const hasAccess = requiredRoles.some(requiredRole => 
        hasRequiredRole(user.role, requiredRole)
      );

      // Framework Mental: Observability - security audit logging
      const logContext = {
        userId: user.id, // In production, hash this
        userRole: user.role,
        requiredRoles,
        hasAccess,
        endpoint: `${context.getClass().name}.${context.getHandler().name}`,
        ip: request.ip,
        userAgent: request.get('User-Agent')
      };

      if (hasAccess) {
        this.logger.log('Access granted', logContext);
      } else {
        this.logger.warn('Access denied - insufficient privileges', logContext);
      }

      return hasAccess;

    } catch (error: unknown) {
      // Framework Mental: Error handling - never fail open
      let errorMessage: string;
      let errorStack: string | undefined;
    
      if (error instanceof Error) {
        errorMessage = error.message;
        errorStack = error.stack;
      } else if (typeof error === 'string') {
        errorMessage = error;
      } else {
        errorMessage = JSON.stringify(error);
      }
    
      this.logger.error('RolesGuard error - denying access', {
        message: errorMessage,
        stack: errorStack,
        handler: context.getHandler().name
      });
      
      return false; // Fail closed - security first
    }
  }
}