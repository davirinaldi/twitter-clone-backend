import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

/**
 * Metadata key for roles decorator
 * Used by Reflector to extract required roles
 */
export const ROLES_KEY = 'roles';

/**
 * Decorator to specify required roles for endpoints
 * 
 * @example
 * ```typescript
 * @Roles(Role.ADMIN)
 * @Get('admin-only')
 * adminOnlyEndpoint() { ... }
 * 
 * @Roles(Role.USER) // or omit decorator for USER access
 * @Get('user-endpoint') 
 * userEndpoint() { ... }
 * ```
 * 
 * @param roles Required roles for accessing the endpoint
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);